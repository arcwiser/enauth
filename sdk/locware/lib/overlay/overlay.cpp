#include "overlay.h"

#define STB_IMAGE_IMPLEMENTATION
#include <lib/imgui/stb_image.h>
static const wchar_t CLASS_NAME[] = L"ovl_fullscreen";

Overlay::Overlay(HWND targetWindow)
    : m_targetWindow(targetWindow), m_hWnd(nullptr), m_hInst(GetModuleHandle(nullptr)),
    m_runningFlag(false), m_clickThrough(true), desired_fps(144), current_width(0), current_height(0)
{
    running = false;
    next_frame_time = std::chrono::high_resolution_clock::now();
}

Overlay::~Overlay()
{
    Destroy();
}

bool Overlay::LoadTexture(const char* file, ID3D11ShaderResourceView** out_srv, int* w, int* h)
{
    int ix, iy, channels;
    unsigned char* data = stbi_load(file, &ix, &iy, &channels, 4);
    if (!data) return false;

    *w = ix;
    *h = iy;

    D3D11_TEXTURE2D_DESC desc = {};
    desc.Width = ix;
    desc.Height = iy;
    desc.MipLevels = 1;
    desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

    D3D11_SUBRESOURCE_DATA sub = {};
    sub.pSysMem = data;
    sub.SysMemPitch = ix * 4;

    ID3D11Texture2D* tex = nullptr;
    m_pd3dDevice->CreateTexture2D(&desc, &sub, &tex);

    D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
    srvDesc.Format = desc.Format;
    srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
    srvDesc.Texture2D.MipLevels = 1;

    m_pd3dDevice->CreateShaderResourceView(tex, &srvDesc, out_srv);
    tex->Release();
    stbi_image_free(data);
    return true;
}

bool Overlay::Create()
{
    if (!InitWindow()) return false;
    if (!InitD3D()) return false;

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;

    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding = 0;
    s.FrameRounding = 0;
    s.ChildRounding = 0;
    s.Colors[ImGuiCol_WindowBg] = ImVec4(0, 0, 0, 1);
    s.Colors[ImGuiCol_ChildBg] = ImVec4(0.05f, 0.05f, 0.05f, 1);
    s.Colors[ImGuiCol_Button] = ImVec4(0.10f, 0.10f, 0.10f, 1);
    s.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.18f, 0.18f, 0.18f, 1);
    s.Colors[ImGuiCol_ButtonActive] = ImVec4(0.25f, 0.25f, 0.25f, 1);
    s.Colors[ImGuiCol_FrameBg] = ImVec4(0.08f, 0.08f, 0.08f, 1);

    ImGui_ImplWin32_Init(m_hWnd);
    ImGui_ImplDX11_Init(m_pd3dDevice.Get(), m_pd3dDeviceContext.Get());

    running = true;
    m_runningFlag.store(true);
    return true;
}

void Overlay::Destroy()
{
    if (!m_hWnd) return;

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupD3D();
    DestroyWindow(m_hWnd);
    UnregisterClassW(CLASS_NAME, m_hInst);

    m_hWnd = nullptr;
    running = false;
    m_runningFlag.store(false);
}

void Overlay::SetDesiredFPS(int fps)
{
    if (fps <= 0) return;
    desired_fps = fps;
}

void Overlay::Start()
{
    auto interval = std::chrono::duration_cast<std::chrono::high_resolution_clock::duration>(
        std::chrono::duration<double>(1.0 / desired_fps)
    );
    auto now = std::chrono::high_resolution_clock::now();
    if (next_frame_time > now)
        std::this_thread::sleep_until(next_frame_time);
    next_frame_time += interval;

    MSG msg;
    while (PeekMessageW(&msg, nullptr, 0U, 0U, PM_REMOVE))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
        if (msg.message == WM_QUIT) { running = false; m_runningFlag.store(false); }
    }

    if (!running) return;

    RECT rc;
    GetClientRect(m_hWnd, &rc);
    UINT w = rc.right - rc.left;
    UINT h = rc.bottom - rc.top;

    if ((int)w != current_width || (int)h != current_height)
    {
        current_width = w;
        current_height = h;
        ImGui_ImplDX11_InvalidateDeviceObjects();
        if (m_mainRenderTargetView) m_mainRenderTargetView.Reset();
        m_pSwapChain->ResizeBuffers(0, w, h, DXGI_FORMAT_UNKNOWN, 0);
        CreateRenderTarget();
        ImGui_ImplDX11_CreateDeviceObjects();
    }

    const float clear_color[4] = { 0,0,0,0 };
    m_pd3dDeviceContext->OMSetRenderTargets(1, m_mainRenderTargetView.GetAddressOf(), nullptr);
    m_pd3dDeviceContext->ClearRenderTargetView(m_mainRenderTargetView.Get(), clear_color);

    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();
}

void Overlay::End()
{
    if (!running) return;
    ImGui::Render();
    m_pd3dDeviceContext->OMSetRenderTargets(1, m_mainRenderTargetView.GetAddressOf(), nullptr);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    m_pSwapChain->Present(0, 0);
}

void Overlay::SetClickThrough(bool enable)
{
    m_clickThrough.store(enable);
    LONG ex = GetWindowLongW(m_hWnd, GWL_EXSTYLE);
    if (enable) SetWindowLongW(m_hWnd, GWL_EXSTYLE, ex | WS_EX_TRANSPARENT);
    else SetWindowLongW(m_hWnd, GWL_EXSTYLE, ex & ~WS_EX_TRANSPARENT);
    SetWindowPos(m_hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
}

HWND Overlay::Window() const { return m_hWnd; }

bool Overlay::InitWindow()
{
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = m_hInst;
    wc.lpszClassName = CLASS_NAME;
    RegisterClassExW(&wc);

    RECT r;
    HWND desktop = GetDesktopWindow();
    GetClientRect(desktop, &r);

    int w = r.right;
    int h = r.bottom;

    m_hWnd = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW | WS_EX_TRANSPARENT,
        CLASS_NAME,
        L"",
        WS_POPUP,
        0, 0, w, h,
        nullptr, nullptr, m_hInst, this);

    if (!m_hWnd) return false;

    MARGINS m = { -1,-1,-1,-1 };
    DwmExtendFrameIntoClientArea(m_hWnd, &m);
    SetLayeredWindowAttributes(m_hWnd, 0, 255, LWA_ALPHA);
    ShowWindow(m_hWnd, SW_SHOWNOACTIVATE);
    UpdateWindow(m_hWnd);

    LONG ex = GetWindowLongW(m_hWnd, GWL_EXSTYLE);
    SetWindowLongW(m_hWnd, GWL_EXSTYLE, ex | WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE);

    RECT rc;
    GetClientRect(m_hWnd, &rc);
    current_width = rc.right - rc.left;
    current_height = rc.bottom - rc.top;

    return true;
}

bool Overlay::InitD3D()
{
    RECT rc;
    GetClientRect(m_hWnd, &rc);
    UINT w = rc.right - rc.left;
    UINT h = rc.bottom - rc.top;

    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = w;
    sd.BufferDesc.Height = h;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = m_hWnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT;
    D3D_FEATURE_LEVEL fl;
    D3D_FEATURE_LEVEL fls[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };

    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, flags,
        fls, 2, D3D11_SDK_VERSION,
        &sd, &m_pSwapChain, &m_pd3dDevice, &fl,
        &m_pd3dDeviceContext);

    if (FAILED(hr)) return false;

    CreateRenderTarget();
    return true;
}

void Overlay::CleanupD3D()
{
    CleanupRenderTarget();
    if (m_pSwapChain) m_pSwapChain.Reset();
    if (m_pd3dDeviceContext) { m_pd3dDeviceContext->ClearState(); m_pd3dDeviceContext.Reset(); }
    if (m_pd3dDevice) m_pd3dDevice.Reset();
}

void Overlay::CreateRenderTarget()
{
    ComPtr<ID3D11Texture2D> bb;
    m_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&bb));
    m_pd3dDevice->CreateRenderTargetView(bb.Get(), nullptr, &m_mainRenderTargetView);
}

void Overlay::CleanupRenderTarget()
{
    if (m_mainRenderTargetView) m_mainRenderTargetView.Reset();
}

LRESULT CALLBACK Overlay::WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    Overlay* o = (Overlay*)GetWindowLongPtrW(hWnd, GWLP_USERDATA);

    if (msg == WM_CREATE)
    {
        CREATESTRUCTW* cs = (CREATESTRUCTW*)lParam;
        o = (Overlay*)cs->lpCreateParams;
        SetWindowLongPtrW(hWnd, GWLP_USERDATA, (LONG_PTR)o);
        return 0;
    }

    if (o)
        if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
            return true;

    switch (msg)
    {
    case WM_SIZE:
        if (o && wParam != SIZE_MINIMIZED)
        {
            o->CleanupRenderTarget();
            if (o->m_pSwapChain)
            {
                o->m_pSwapChain->ResizeBuffers(0, LOWORD(lParam), HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
                o->CreateRenderTarget();
            }
        }
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

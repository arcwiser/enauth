#pragma once
#include <windows.h>
#include <d3d11.h>
#include <wrl.h>
#include <atomic>
#include <chrono>
#include <thread>
#include <dwmapi.h>
#include <lib/imgui/imgui.h>
#include <lib/imgui/imgui_impl_win32.h>
#include <lib/imgui/imgui_impl_dx11.h>

#pragma comment(lib,"d3d11.lib")
#pragma comment(lib,"dwmapi.lib")
using Microsoft::WRL::ComPtr;

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

class Overlay
{
public:
    Overlay(HWND targetWindow = nullptr);
    ~Overlay();

    bool running;
    bool Create();
    void Destroy();
    void Start();
    void End();
    void SetClickThrough(bool enable);
    void SetDesiredFPS(int fps);
    HWND Window() const;

    int desired_fps;

    bool LoadTexture(const char* file, ID3D11ShaderResourceView** out_srv, int* w, int* h);

private:
    bool InitWindow();
    bool InitD3D();
    void CleanupD3D();
    void CreateRenderTarget();
    void CleanupRenderTarget();
    void MainLoopIteration();

    static LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
    HWND m_targetWindow;
    HWND m_hWnd;
    HINSTANCE m_hInst;

    ComPtr<ID3D11Device>            m_pd3dDevice;
    ComPtr<ID3D11DeviceContext>     m_pd3dDeviceContext;
    ComPtr<IDXGISwapChain>          m_pSwapChain;
    ComPtr<ID3D11RenderTargetView>  m_mainRenderTargetView;

    std::atomic<bool> m_runningFlag;
    std::atomic<bool> m_clickThrough;

    int current_width;
    int current_height;
    std::chrono::high_resolution_clock::time_point next_frame_time;
};

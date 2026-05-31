#include <enauth.h>

#include <lib/overlay/overlay.h>
#include <cheat/entity.h>

#include <chrono>
#include <iostream>
#include <string>
#include <thread>

bool boxes = false;

namespace {

struct LoaderConfig {
    std::string server_url = "http://localhost:8080";
    std::string app_id = "29407018-8dd4-4ca6-a0ec-9d99e0ef7ab9";
    std::string app_secret = "3e6162adb24ea2d879bb327761efa8635358b92fc5a49a07106c05c3d55800fac3f9cff9b5ab76ad0cbc9a070bbfd8668a45e3f2af1edb8480e541ea9ce86bae";
    std::string version = "1.0.0";
};

std::string PromptLicenseKey() {
    std::cout << "Enter license key: ";
    std::string license_key;
    std::getline(std::cin, license_key);
    while (!license_key.empty() && (license_key.back() == '\r' || license_key.back() == '\n' || license_key.back() == ' ' || license_key.back() == '\t')) {
        license_key.pop_back();
    }
    while (!license_key.empty() && (license_key.front() == ' ' || license_key.front() == '\t')) {
        license_key.erase(license_key.begin());
    }
    return license_key;
}

void PrintFailure(const char* stage, const std::string& message) {
    std::cout << "[" << stage << "] " << message << std::endl;
}

const char* StatusName(enauth::Status status) {
    switch (status) {
    case enauth::Status::Success: return "Success";
    case enauth::Status::InvalidApp: return "InvalidApp";
    case enauth::Status::OutdatedVersion: return "OutdatedVersion";
    case enauth::Status::InvalidKey: return "InvalidKey";
    case enauth::Status::ExpiredKey: return "ExpiredKey";
    case enauth::Status::BannedKey: return "BannedKey";
    case enauth::Status::BannedHwid: return "BannedHwid";
    case enauth::Status::MaxHwids: return "MaxHwids";
    case enauth::Status::SessionExpired: return "SessionExpired";
    case enauth::Status::NetworkError: return "NetworkError";
    case enauth::Status::ServerError: return "ServerError";
    case enauth::Status::DecryptError: return "DecryptError";
    case enauth::Status::ReplayAttack: return "ReplayAttack";
    case enauth::Status::LevelRequired: return "LevelRequired";
    case enauth::Status::LevelNotAllowed: return "LevelNotAllowed";
    case enauth::Status::SuspiciousLogin: return "SuspiciousLogin";
    default: return "Unknown";
    }
}

void PrintResultFailure(const char* stage, const enauth::Status status, const std::string& message) {
    std::cout << "[" << stage << "] " << StatusName(status);
    if (!message.empty()) {
        std::cout << " - " << message;
    }
    std::cout << std::endl;
}

void ShowExpirySplash(const std::string& expires_at) {
    std::cout << "[loader] License expires at: "
              << (expires_at.empty() ? "unknown" : expires_at)
              << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(3));
}

void RunProgram() {
    Overlay overlay(nullptr);
    if (!overlay.Create()) {
        std::cout << "[loader] Failed to create overlay." << std::endl;
        return;
    }

    bool clickThrough = true;
    overlay.SetClickThrough(true);

    ID3D11ShaderResourceView* logoTex = nullptr;
    int logoW = 0, logoH = 0;
    overlay.LoadTexture("img/logo.png", &logoTex, &logoW, &logoH);

    const char* tabs[] = { "Visuals", "Settings", "Debug" };
    int currentTab = 0;

    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 12.0f;
    style.FrameRounding = 8.0f;
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.1f, 0.1f, 0.12f, 0.95f);
    style.Colors[ImGuiCol_ChildBg] = ImVec4(0.15f, 0.15f, 0.18f, 0.95f);
    style.Colors[ImGuiCol_Button] = ImVec4(0.2f, 0.2f, 0.25f, 1.0f);
    style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.35f, 0.35f, 0.4f, 1.0f);
    style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.15f, 0.15f, 0.18f, 1.0f);

    ImVec4 selectedColor = ImVec4(0.2f, 0.4f, 1.0f, 1.0f);

    init();

    while (overlay.running)
    {
        vm = mem->ReadMemory<view_matrix_t>(client + cs2_dumper::offsets::client_dll::dwViewMatrix);
        if (GetAsyncKeyState(VK_INSERT) & 1)
        {
            clickThrough = !clickThrough;
            overlay.SetClickThrough(clickThrough);
        }

        overlay.Start();

        {
            ImGui::SetNextWindowPos(ImVec2(10, 10), ImGuiCond_Always);
            ImGui::SetNextWindowBgAlpha(0.85f);
            ImGui::Begin("watermark", nullptr,
                ImGuiWindowFlags_NoTitleBar |
                ImGuiWindowFlags_NoResize |
                ImGuiWindowFlags_NoCollapse |
                ImGuiWindowFlags_NoMove |
                ImGuiWindowFlags_AlwaysAutoResize |
                ImGuiWindowFlags_NoSavedSettings);

            ImGui::Image((ImTextureID)logoTex, ImVec2(18.0f, 18.0f));
            ImGui::SameLine(0, 5);
            ImGui::Text("LOCWARE | FPS -> %.1f", ImGui::GetIO().Framerate);

            ImGui::End();
        }

        if (!clickThrough)
        {
            ImGui::SetNextWindowPos(ImVec2(80, 80), ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowSize(ImVec2(520, 380), ImGuiCond_FirstUseEver);

            ImGui::Begin("LOCWARE", nullptr,
                ImGuiWindowFlags_NoTitleBar |
                ImGuiWindowFlags_NoCollapse |
                ImGuiWindowFlags_NoSavedSettings |
                ImGuiWindowFlags_NoResize);

            ImGui::SetCursorPos(ImVec2(10, 10));
            ImGui::Image((ImTextureID)logoTex, ImVec2((float)logoW, (float)logoH));
            ImGui::SameLine();
            ImGui::SetCursorPosY(10 + (logoH / 2) - ImGui::GetTextLineHeight() / 2);
            ImGui::Text("LOCWARE");

            ImGui::SetCursorPosY((float)logoH + 20);
            ImGui::BeginChild("Content", ImVec2(0, 0), true);

            ImGui::BeginChild("Tabs", ImVec2(130, 0), true);
            for (int i = 0; i < 3; i++)
            {
                ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 8));
                bool pushedColor = false;
                if (i == currentTab)
                {
                    ImGui::PushStyleColor(ImGuiCol_Button, selectedColor);
                    pushedColor = true;
                }

                if (ImGui::Button(tabs[i], ImVec2(110, 40)))
                    currentTab = i;

                if (pushedColor)
                    ImGui::PopStyleColor();

                ImGui::PopStyleVar();
                ImGui::Spacing();
            }
            ImGui::EndChild();

            ImGui::SameLine();
            ImGui::BeginChild("MainContent", ImVec2(0, 0), true);
            switch (currentTab)
            {
            case 0:
                ImGui::Text("Visual");
                ImGui::Separator();
                ImGui::Checkbox("Box ESP", &boxes);
                break;
            case 1:
                ImGui::Text("Settings");
                ImGui::Separator();
                ImGui::SliderInt("Overlay FPS", &overlay.desired_fps, 30, 500);
                break;
            case 2:
                ImGui::Text("Debug");
                ImGui::Separator();
                ImVec4 validColor = ImVec4(0.0f, 1.0f, 0.0f, 1.0f);
                ImVec4 invalidColor = ImVec4(1.0f, 0.0f, 0.0f, 1.0f);

                ImGui::TextColored(client ? validColor : invalidColor, "Client: 0x%p", (void*)client);
                ImGui::TextColored(server ? validColor : invalidColor, "Server: 0x%p", (void*)server);
                ImGui::TextColored(engine ? validColor : invalidColor, "Engine: 0x%p", (void*)engine);

                ImGui::Text("Player Count:");
                ImGui::SameLine();
                if (playercount <= 0)
                    ImGui::TextColored(invalidColor, "No Players");
                else
                    ImGui::TextColored(validColor, "%d", playercount);
                break;
            }
            ImGui::EndChild();

            ImGui::EndChild();
            ImGui::End();
        }

        for (const auto& actor : cache) {
            if (boxes)
            {
                vec3 head_t = { actor.pos.x, actor.pos.y, actor.pos.z + 70.f };
                vec2 screenhead = head_t.W2S(head_t, vm, WIDTH, HEIGHT);
                vec2 screenpos = actor.pos.W2S(actor.pos, vm, WIDTH, HEIGHT);
                if (screenhead.IsNull() || screenpos.IsNull()) continue;

                float height = std::abs(screenpos.y - screenhead.y);
                float width = height / 2.35f;

                vec2 topLeft(screenhead.x - width / 2, screenhead.y);
                vec2 bottomRight(topLeft.x + width, topLeft.y + height);

                ImGui::GetBackgroundDrawList()->AddRect(ImVec2(topLeft.x, topLeft.y), ImVec2(bottomRight.x, bottomRight.y), IM_COL32(255, 255, 255, 255), 0.0f, 0, 1.5f);
            }
        }

        overlay.End();
    }

    overlay.Destroy();
}

} // namespace

int main()
{
    SetConsoleTitleA("LOCWARE Loader");

    std::cout << "========================================" << std::endl;
    std::cout << "           LOCWARE Console Loader       " << std::endl;
    std::cout << "========================================" << std::endl;

    const LoaderConfig cfg = {};
    const std::string license_key = PromptLicenseKey();
    if (license_key.empty()) {
        std::cout << "[loader] No license key entered." << std::endl;
        return 1;
    }

    std::cout << "[1/3] Initializing EnAuth..." << std::endl;
    enauth::Client auth(cfg.server_url, cfg.app_id, cfg.app_secret, cfg.version);

    const auto init = auth.Init();
    if (!init.success) {
        PrintResultFailure("init", init.status, init.message);
        return 1;
    }

    std::cout << "[2/3] Logging in..." << std::endl;
    const auto login = auth.Login(license_key);
    if (!login.success) {
        PrintResultFailure("login", login.status, login.message);
        return 1;
    }

    std::cout << "[3/3] Authentication complete." << std::endl;
    ShowExpirySplash(login.expires_at.empty() ? auth.GetExpiresAt() : login.expires_at);
    std::cout << "[loader] Launching program..." << std::endl;
    RunProgram();

    auth.Logout();
    std::cout << "[loader] Closed cleanly." << std::endl;
    return 0;
}

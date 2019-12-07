// Axel '0vercl0k' Souchet - November 24 2019
// Special thanks to kaze for his previous work on funny payloads as well as answering
// my questions :) http://fat.malcat.fr/PayloadBaboons.html
//
#undef UNICODE
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <ctime>
#include <gdiplus.h>

#include "sprites.h"

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI RtlGetCompressionWorkSpaceSize(
  USHORT CompressionFormatAndEngine,
  PULONG CompressBufferWorkSpaceSize,
  PULONG CompressFragmentWorkSpaceSize
);

extern "C" NTSTATUS NTAPI RtlDecompressBufferEx(
  USHORT CompressionFormat,
  PUCHAR UncompressedBuffer,
  ULONG  UncompressedBufferSize,
  PUCHAR CompressedBuffer,
  ULONG  CompressedBufferSize,
  PULONG FinalUncompressedSize,
  PVOID  WorkSpace
);

const char *kClassName = "Doar-e";
const char *kWindowName = "Diary of a reverse-engineer";
const uint32_t kNumberOfWindows = 20;
const uint32_t kScaleFactor = 1;

struct State_t {
    uint32_t BitmapHeight;
    uint32_t BitmapWidth;
    uint32_t WindowWidth;
    uint32_t WindowHeight;

    uint32_t CurrentSpriteIdx;
    uint32_t NumberOfSprites;
    Sprite_t *Sprites;

    HWND Windows[kNumberOfWindows];

    BITMAPINFO *Bitmap;
};

uint32_t rand_ab(const uint32_t min, const uint32_t max) {
    return min + (rand() % (max - min));
}

bool NT_SUCCESS(NTSTATUS Status) {
    return Status >= 0;
}

bool UpdateSprite(State_t *State) {
    State->CurrentSpriteIdx++;
    State->CurrentSpriteIdx %= State->NumberOfSprites;
    return true;
}

bool DrawSprite(const State_t *State, HDC Dc) {
    const Sprite_t *CurrentSprite = State->Sprites + State->CurrentSpriteIdx;
    int Result = StretchDIBits(
        Dc,
        0,
        0,
        State->WindowWidth,
        State->WindowHeight,
        0,
        0,
        State->BitmapWidth,
        State->BitmapHeight,
        CurrentSprite->Bytes,
        State->Bitmap,
        DIB_RGB_COLORS,
        SRCCOPY
    );

    if(Result == 0) {
        PostQuitMessage(0);
        return false;
    }

    return true;
}

LRESULT CALLBACK WindowProc(
    HWND Hwnd,
    UINT Msg,
    WPARAM WParam,
    LPARAM LParam
) {
    switch(Msg) {

        //
        // Do a bunch of initialization at creation time.
        //

        case WM_CREATE: {

            //
            // Set opacity / transparency.
            //

            SetLayeredWindowAttributes(
                Hwnd,
                kTransparentColor,
                0xff,
                LWA_COLORKEY | LWA_ALPHA
            );

            //
            // Display the window.
            //

            ShowWindow(Hwnd, SW_SHOW);
            break;
        }

        //
        // Break out of the main loop to exit the process.
        //

        case WM_DESTROY: {
            PostQuitMessage(0);
            break;
        }

        //
        // Time to update the sprite - only the 'master' window receives it.
        //

        case WM_TIMER: {
            State_t *State = (State_t*)GetWindowLongPtr(Hwnd, GWLP_USERDATA);
            UpdateSprite(State);

            //
            // Invalidate everybody's window so that they can paint the new state.
            //

            for(size_t Idx = 0; Idx < kNumberOfWindows; Idx++) {
                HWND Window = State->Windows[Idx];
                InvalidateRect(Window, nullptr, false);
            }

            break;
        }

        //
        // Time to draw the sprite.
        //

        case WM_PAINT: {
            const State_t *State = (State_t*)GetWindowLongPtr(Hwnd, GWLP_USERDATA);
            PAINTSTRUCT Paint;
            HDC Dc;

            Dc = BeginPaint(Hwnd, &Paint);
            DrawSprite(State, Dc);
            EndPaint(Hwnd, &Paint);
            break;
        }

        //
        // Pass down the other messages to the default window procedure.
        //

        default: {
            return DefWindowProc(Hwnd, Msg, WParam, LParam);
        }
    }

    return 0;
}

int WINAPI WinMain(
    HINSTANCE Instance,
    HINSTANCE PrevInstance,
    PSTR CmdLine,
    int CmdShow
) {

    WNDCLASS WindowClass;
    RECT DesktopRect;
    HWND MasterWindow = nullptr;
    BITMAPINFO *Bitmap;
    State_t State;
    Sprite_t *Sprites;

    //
    // Initialize the PRNG.
    //

    srand(uint32_t(time(nullptr)));

    //
    // Decompress our stuff once and for all.
    //

    static_assert(
        (kNumberOfSprites * sizeof(Sprite_t)) == kUncompressedSize,
        "The number of sprites should match the decompressed size."
    );

    Sprites = new Sprite_t[kNumberOfSprites];
    if(Sprites == nullptr) {
        return EXIT_FAILURE;
    }

    ULONG Dummy;
    ULONG WorkspaceSize = 0;
    if(!NT_SUCCESS(RtlGetCompressionWorkSpaceSize(
        kCompressionFormat,
        &WorkspaceSize,
        &Dummy
    ))) {
        return EXIT_FAILURE;
    }

    uint8_t *Workspace = new uint8_t[WorkspaceSize];
    if(Workspace == nullptr) {
        return EXIT_FAILURE;
    }

    if(!NT_SUCCESS(RtlDecompressBufferEx(
        kCompressionFormat,
        PUCHAR(Sprites),
        kUncompressedSize,
        PUCHAR(kCompressedSprites),
        sizeof(kCompressedSprites),
        &Dummy,
        Workspace
    ))) {
        return EXIT_FAILURE;
    }

    delete[] Workspace;
    Workspace = nullptr;

    //
    // Initialize the bitmap with our sprite data.
    //

    static_assert(
        kSpriteSize == (kSpriteWidth * kSpriteHeight),
        "The code assumes that the array is a list of RGB values."
    );

    const size_t kBitmapSize = sizeof(BITMAPINFO) + (256 * sizeof(RGBQUAD));
    Bitmap = LPBITMAPINFO(new uint8_t[kBitmapSize]);
    if(Bitmap == nullptr) {
        return EXIT_FAILURE;
    }

    Bitmap->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    // The bitmap has a maximum of 256 colors, and the bmiColors member contains up
    // to 256 entries. In this case, each byte in the array represents a single pixel.
    Bitmap->bmiHeader.biBitCount = 8;
    // Need to use a negative height if we want StretchDIBits to display the sprite
    // not upside down.
    Bitmap->bmiHeader.biHeight = -LONG(kSpriteHeight);
    Bitmap->bmiHeader.biWidth = kSpriteWidth;
    Bitmap->bmiHeader.biPlanes = 1;
    Bitmap->bmiHeader.biCompression = BI_RGB;

    //
    // Initialize the color palette.
    //

    static_assert(
        sizeof(kPalette) == (256 * sizeof(RGBQUAD)),
        "The code assumes that the palette is 256 RGBQUAD."
    );

    memcpy(Bitmap->bmiColors, kPalette, sizeof(kPalette));

    //
    // Register the window class for our window.
    //

    memset(&WindowClass, 0, sizeof(WNDCLASS));
    WindowClass.hCursor = LoadCursor(nullptr, IDC_ARROW);
    WindowClass.hInstance = Instance;
    WindowClass.lpfnWndProc = WindowProc;
    WindowClass.lpszClassName = kClassName;

    if(RegisterClass(&WindowClass) == 0) {
        return EXIT_FAILURE;
    }

    //
    // Initialize our global state.
    //

    State.Bitmap = Bitmap;
    State.BitmapHeight = kSpriteHeight;
    State.BitmapWidth = kSpriteWidth;
    State.WindowHeight = State.BitmapHeight * kScaleFactor;
    State.WindowWidth = State.BitmapWidth * kScaleFactor;
    State.CurrentSpriteIdx = 0;
    State.NumberOfSprites = kNumberOfSprites;
    State.Sprites = Sprites;

    //
    // Get the dimensions of the desktop.
    //

    if(!GetWindowRect(GetDesktopWindow(), &DesktopRect)) {
        return EXIT_FAILURE;
    }

    //
    // Create the window using the previously registered class.
    //

    for(size_t Idx = 0; Idx < kNumberOfWindows; Idx++) {

        //
        // Pick a random position for the window.
        //

        const uint32_t kWindowX = rand_ab(0, DesktopRect.right - State.WindowWidth);
        const uint32_t kWindowY = rand_ab(0, DesktopRect.bottom - State.WindowHeight);

        State.Windows[Idx] = CreateWindowEx(
            // Layered Windows:
            //   https://docs.microsoft.com/en-us/windows/win32/winmsg/window-features#layered-windows
            WS_EX_TOPMOST | WS_EX_LAYERED,
            kClassName,
            kWindowName,
            WS_POPUP,
            kWindowX,
            kWindowY,
            State.WindowWidth,
            State.WindowHeight,
            nullptr,
            nullptr,
            Instance,
            0
        );

        if(State.Windows[Idx] == nullptr) {
            return EXIT_FAILURE;
        }

        //
        // Tie up the state with the Window.
        //

        SetWindowLongPtr(State.Windows[Idx], GWLP_USERDATA, LONG_PTR(&State));
    }

    //
    // Configure timer to refresh the sprite.
    //

    const uint32_t kTimerId = 1;
    SetTimer(State.Windows[0], kTimerId, 125, nullptr);

    //
    // Message loop.
    //

    MSG Message;
    while(GetMessage(&Message, nullptr, 0, 0) > 0) {
        TranslateMessage(&Message);
        DispatchMessage(&Message);
    }

    return EXIT_SUCCESS;
}
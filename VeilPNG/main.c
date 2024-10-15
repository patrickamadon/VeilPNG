// main.c

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <bcrypt.h>
#define _CRT_SECURE_NO_WARNINGS
#include <commdlg.h>   // For common dialogs
#include <shlobj.h>    // For folder selection
#include <tchar.h>     // For _T and TCHAR
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sal.h>       // For annotations
#include <commctrl.h>  // For progress bar and common controls
#include <time.h>      // For time()

#include "encryption.h"
#include "data_embed.h"
#include "sveil_steganography.h"  // Include the steganography header
#include "instructions.h"       // Include the instructions text

#pragma comment(lib, "Comctl32.lib")  // Link with Comctl32.lib for common controls
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "zlibstat.lib")

// Define control IDs
#define IDC_PNG_PATH_BUTTON          101
#define IDC_HIDDEN_FILE_BUTTON       102
#define IDC_CREATE_VEIL_BUTTON       103
#define IDC_EXTRACT_VEIL_BUTTON      104
#define IDC_INSTRUCTIONS_BUTTON      105
#define IDC_SHOW_PASSWORD_CHECKBOX   106
#define IDC_CREATE_SVEIL_BUTTON      107
#define IDC_EXTRACT_SVEIL_BUTTON     108

#define WM_UPDATE_STATUS_TEXT (WM_USER + 1)

// Global variables
HINSTANCE hInst;
HWND hCreateVeilButton, hExtractVeilButton, hInstructionsButton;
HWND hCreateSVeilButton, hExtractSVeilButton;  // sVeil buttons
HWND hPngPathEdit, hHiddenFileEdit, hPasswordEdit;
HWND hPngPathButton, hHiddenFileButton;
HWND hByAmadonText;
HWND hProgressBar;           // Progress bar
HWND hStatusText;            // Status text
HWND hShowPasswordCheckbox;  // Show Password checkbox

HFONT hFont;  // Font handle

// Function declarations
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK InstructionsWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
DWORD WINAPI CreateVeilThread(LPVOID);
DWORD WINAPI ExtractVeilThread(LPVOID);
DWORD WINAPI CreateSVeilThread(LPVOID);
DWORD WINAPI ExtractSVeilThread(LPVOID);
void CreateVeil(HWND);
void ExtractVeil(HWND);
void CreateSVeil(HWND);
void ExtractSVeil(HWND);
BOOL OpenFileDialog(HWND, LPTSTR, DWORD, LPCTSTR);
BOOL SaveFileDialog(HWND, LPTSTR, DWORD, LPCTSTR);
BOOL SelectFolderDialog(HWND hwnd, LPTSTR folderPath, DWORD folderPathSize);
void ShowInstructions(HWND hwnd);
void ClearInputFields();  // Function to clear input fields
BOOL IsPasswordStrong(const TCHAR* password);  // Password strength validation

int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPTSTR lpCmdLine,
    _In_ int nCmdShow) {

    // Seed the random number generator
    srand((unsigned int)time(NULL));

    hInst = hInstance;
    HWND hwnd;
    MSG msg;
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = _T("VeilPNGClass");
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    if (!RegisterClass(&wc)) {
        MessageBox(NULL, _T("Window Registration Failed!"), _T("Error"), MB_ICONERROR | MB_OK);
        return 0;
    }

    hwnd = CreateWindow(wc.lpszClassName, _T("VeilPNG"),
        WS_OVERLAPPEDWINDOW & ~(WS_THICKFRAME | WS_MAXIMIZEBOX),
        CW_USEDEFAULT, CW_USEDEFAULT, 500, 440,
        NULL, NULL, hInstance, NULL);

    if (hwnd == NULL) {
        MessageBox(NULL, _T("Window Creation Failed!"), _T("Error"), MB_ICONERROR | MB_OK);
        return 0;
    }

    // Initialize common controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icex);

    // Create the font
    hFont = CreateFont(
        18,                        // Height
        0,                         // Width
        0,                         // Escapement
        0,                         // Orientation
        FW_NORMAL,                 // Weight
        FALSE,                     // Italic
        FALSE,                     // Underline
        FALSE,                     // StrikeOut
        DEFAULT_CHARSET,           // CharSet
        OUT_DEFAULT_PRECIS,        // OutPrecision
        CLIP_DEFAULT_PRECIS,       // ClipPrecision
        DEFAULT_QUALITY,           // Quality
        DEFAULT_PITCH | FF_SWISS,  // PitchAndFamily
        _T("Segoe UI"));           // Font name

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    // Clean up font
    DeleteObject(hFont);
    return (int)msg.wParam;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        // PNG File Label and Edit
    {
        HWND hStatic = CreateWindow(_T("STATIC"), _T("PNG File:"), WS_VISIBLE | WS_CHILD,
            20, 20, 80, 25, hwnd, NULL, hInst, NULL);
        SendMessage(hStatic, WM_SETFONT, (WPARAM)hFont, TRUE);

        hPngPathEdit = CreateWindow(_T("EDIT"), _T(""), WS_VISIBLE | WS_CHILD | WS_BORDER,
            110, 20, 250, 25, hwnd, NULL, hInst, NULL);
        SendMessage(hPngPathEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

        hPngPathButton = CreateWindow(_T("BUTTON"), _T("Browse..."), WS_VISIBLE | WS_CHILD,
            370, 20, 80, 25, hwnd, (HMENU)IDC_PNG_PATH_BUTTON, hInst, NULL);
        SendMessage(hPngPathButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    }

    // Hidden File Label and Edit
    {
        HWND hStatic = CreateWindow(_T("STATIC"), _T("Hidden File:"), WS_VISIBLE | WS_CHILD,
            20, 60, 100, 25, hwnd, NULL, hInst, NULL);
        SendMessage(hStatic, WM_SETFONT, (WPARAM)hFont, TRUE);

        hHiddenFileEdit = CreateWindow(_T("EDIT"), _T(""), WS_VISIBLE | WS_CHILD | WS_BORDER,
            110, 60, 250, 25, hwnd, NULL, hInst, NULL);
        SendMessage(hHiddenFileEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

        hHiddenFileButton = CreateWindow(_T("BUTTON"), _T("Browse..."), WS_VISIBLE | WS_CHILD,
            370, 60, 80, 25, hwnd, (HMENU)IDC_HIDDEN_FILE_BUTTON, hInst, NULL);
        SendMessage(hHiddenFileButton, WM_SETFONT, (WPARAM)hFont, TRUE);
    }

    // Password Label and Edit
    {
        HWND hStatic = CreateWindow(_T("STATIC"), _T("Password:"), WS_VISIBLE | WS_CHILD,
            20, 100, 80, 25, hwnd, NULL, hInst, NULL);
        SendMessage(hStatic, WM_SETFONT, (WPARAM)hFont, TRUE);

        hPasswordEdit = CreateWindow(_T("EDIT"), _T(""), WS_VISIBLE | WS_CHILD | WS_BORDER | ES_PASSWORD,
            110, 100, 250, 25, hwnd, NULL, hInst, NULL);
        SendMessage(hPasswordEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
        // Set the password character to '*'
        SendMessage(hPasswordEdit, EM_SETPASSWORDCHAR, (WPARAM)'*', 0);

        // Show Password Checkbox
        hShowPasswordCheckbox = CreateWindow(_T("BUTTON"), _T("Show Password"), WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
            110, 130, 150, 25, hwnd, (HMENU)IDC_SHOW_PASSWORD_CHECKBOX, hInst, NULL);
        SendMessage(hShowPasswordCheckbox, WM_SETFONT, (WPARAM)hFont, TRUE);
    }

    // Button positions
    int buttonYPosition = 170;  // Align all buttons vertically
    int buttonWidth = 110;      // Uniform button width
    int buttonHeight = 30;
    int buttonSpacing = 10;
    int totalButtonWidth = 2 * (buttonWidth + buttonSpacing) - buttonSpacing;
    int startX = (500 - totalButtonWidth) / 2;

    // Create Veil Button
    hCreateVeilButton = CreateWindow(_T("BUTTON"), _T("Create Veil"), WS_VISIBLE | WS_CHILD,
        startX, buttonYPosition, buttonWidth, buttonHeight, hwnd, (HMENU)IDC_CREATE_VEIL_BUTTON, hInst, NULL);
    SendMessage(hCreateVeilButton, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Extract Veil Button
    hExtractVeilButton = CreateWindow(_T("BUTTON"), _T("Extract Veil"), WS_VISIBLE | WS_CHILD,
        startX + buttonWidth + buttonSpacing, buttonYPosition, buttonWidth, buttonHeight, hwnd, (HMENU)IDC_EXTRACT_VEIL_BUTTON, hInst, NULL);
    SendMessage(hExtractVeilButton, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Create sVeil Button (below Create Veil)
    hCreateSVeilButton = CreateWindow(_T("BUTTON"), _T("Create sVeil"), WS_VISIBLE | WS_CHILD,
        startX, buttonYPosition + buttonHeight + 10, buttonWidth, buttonHeight, hwnd, (HMENU)IDC_CREATE_SVEIL_BUTTON, hInst, NULL);
    SendMessage(hCreateSVeilButton, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Extract sVeil Button (below Extract Veil)
    hExtractSVeilButton = CreateWindow(_T("BUTTON"), _T("Extract sVeil"), WS_VISIBLE | WS_CHILD,
        startX + buttonWidth + buttonSpacing, buttonYPosition + buttonHeight + 10, buttonWidth, buttonHeight, hwnd, (HMENU)IDC_EXTRACT_SVEIL_BUTTON, hInst, NULL);
    SendMessage(hExtractSVeilButton, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Instructions Button (centered below other buttons)
    hInstructionsButton = CreateWindow(_T("BUTTON"), _T("Instructions"), WS_VISIBLE | WS_CHILD,
        (500 - buttonWidth) / 2, buttonYPosition + 2 * (buttonHeight + 10), buttonWidth, buttonHeight, hwnd, (HMENU)IDC_INSTRUCTIONS_BUTTON, hInst, NULL);
    SendMessage(hInstructionsButton, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Progress Bar (Initially hidden)
    hProgressBar = CreateWindowEx(0, PROGRESS_CLASS, NULL, WS_CHILD,
        50, 300, 400, 20, hwnd, NULL, hInst, NULL);

    // Status Text (Adjusted for multiline and text wrapping)
    hStatusText = CreateWindow(_T("STATIC"), _T(""), WS_VISIBLE | WS_CHILD | SS_LEFT | SS_EDITCONTROL,
        10, 330, 480, 40, hwnd, NULL, hInst, NULL);
    SendMessage(hStatusText, WM_SETFONT, (WPARAM)hFont, TRUE);

    // "by Amadon" Text (Adjusted position)
    hByAmadonText = CreateWindow(_T("STATIC"), _T("by Amadon"), WS_VISIBLE | WS_CHILD | SS_CENTER,
        0, 380, 500, 20, hwnd, NULL, hInst, NULL);
    SendMessage(hByAmadonText, WM_SETFONT, (WPARAM)hFont, TRUE);

    break;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_PNG_PATH_BUTTON:  // Browse PNG File
        {
            TCHAR fileName[MAX_PATH] = _T("");
            if (OpenFileDialog(hwnd, fileName, MAX_PATH, _T("PNG Files\0*.png\0All Files\0*.*\0"))) {
                SetWindowText(hPngPathEdit, fileName);
            }
            break;
        }
        case IDC_HIDDEN_FILE_BUTTON:  // Browse Hidden File
        {
            TCHAR fileName[MAX_PATH] = _T("");
            if (OpenFileDialog(hwnd, fileName, MAX_PATH, _T("All Files\0*.*\0"))) {
                SetWindowText(hHiddenFileEdit, fileName);
            }
            break;
        }
        case IDC_CREATE_VEIL_BUTTON:  // Create Veil
            CreateVeil(hwnd);
            break;
        case IDC_EXTRACT_VEIL_BUTTON:  // Extract Veil
            ExtractVeil(hwnd);
            break;
        case IDC_CREATE_SVEIL_BUTTON:  // Create sVeil
            CreateSVeil(hwnd);
            break;
        case IDC_EXTRACT_SVEIL_BUTTON:  // Extract sVeil
            ExtractSVeil(hwnd);
            break;
        case IDC_INSTRUCTIONS_BUTTON:  // Instructions
            ShowInstructions(hwnd);
            break;
        case IDC_SHOW_PASSWORD_CHECKBOX:  // Show Password Checkbox
            if (HIWORD(wParam) == BN_CLICKED) {
                BOOL isChecked = (SendMessage(hShowPasswordCheckbox, BM_GETCHECK, 0, 0) == BST_CHECKED);
                if (isChecked) {
                    // Remove the password character to show the password
                    SendMessage(hPasswordEdit, EM_SETPASSWORDCHAR, 0, 0);
                }
                else {
                    // Set the password character to mask the password
                    SendMessage(hPasswordEdit, EM_SETPASSWORDCHAR, (WPARAM)'*', 0);
                }
                // Force the edit control to redraw
                InvalidateRect(hPasswordEdit, NULL, TRUE);
            }
            break;
        }
        break;
    case WM_UPDATE_STATUS_TEXT:
    {
        TCHAR* message = (TCHAR*)lParam;
        SetWindowText(hStatusText, message);
        free(message);  // Free the duplicated string
        break;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

void ShowInstructions(HWND hwndParent) {
    static const TCHAR* INSTRUCTIONS_CLASS_NAME = _T("InstructionsWindowClass");
    static BOOL isRegistered = FALSE;

    if (!isRegistered) {
        WNDCLASS wc = { 0 };
        wc.lpfnWndProc = InstructionsWndProc;
        wc.hInstance = hInst;
        wc.lpszClassName = INSTRUCTIONS_CLASS_NAME;
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);

        if (!RegisterClass(&wc)) {
            return;
        }
        isRegistered = TRUE;
    }

    // Create the instructions window
    HWND hwndInstructions = CreateWindowEx(
        WS_EX_DLGMODALFRAME | WS_EX_WINDOWEDGE,
        INSTRUCTIONS_CLASS_NAME,
        _T("Instructions"),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE | WS_SIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        600, 400,
        hwndParent,
        NULL,
        hInst,
        NULL
    );

    if (!hwndInstructions) {
        return;
    }

    // Create a read-only, multiline edit control to display the instructions
    HWND hEdit = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        _T("EDIT"),
        _T(""),
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT | ES_MULTILINE | ES_READONLY,
        10, 10,
        560, 340,
        hwndInstructions,
        NULL,
        hInst,
        NULL
    );

    SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Set the text of the edit control to the instructionsText
    SetWindowText(hEdit, instructionsText);

    // Adjust the edit control to fit the window
    RECT rcClient;
    GetClientRect(hwndInstructions, &rcClient);
    SetWindowPos(hEdit, NULL, 10, 10, rcClient.right - 20, rcClient.bottom - 20, SWP_NOZORDER);

    // Center the instructions window relative to the parent window
    RECT rcParent, rcInstr;
    GetWindowRect(hwndParent, &rcParent);
    GetWindowRect(hwndInstructions, &rcInstr);

    int posX = rcParent.left + (rcParent.right - rcParent.left - (rcInstr.right - rcInstr.left)) / 2;
    int posY = rcParent.top + (rcParent.bottom - rcParent.top - (rcInstr.bottom - rcInstr.top)) / 2;
    SetWindowPos(hwndInstructions, NULL, posX, posY, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

LRESULT CALLBACK InstructionsWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_SIZE:
    {
        HWND hEdit = FindWindowEx(hwnd, NULL, _T("EDIT"), NULL);
        if (hEdit) {
            RECT rcClient;
            GetClientRect(hwnd, &rcClient);
            SetWindowPos(hEdit, NULL, 10, 10, rcClient.right - 20, rcClient.bottom - 20, SWP_NOZORDER);
        }
    }
    break;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        break;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

void CreateVeil(HWND hwnd) {
    // Disable buttons
    EnableWindow(hCreateVeilButton, FALSE);
    EnableWindow(hExtractVeilButton, FALSE);
    EnableWindow(hCreateSVeilButton, FALSE);
    EnableWindow(hExtractSVeilButton, FALSE);

    // Show and reset progress bar
    SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
    ShowWindow(hProgressBar, SW_SHOW);

    SetWindowText(hStatusText, _T("Creating veil..."));

    // Create a thread to perform the operation
    HANDLE hThread = CreateThread(NULL, 0, CreateVeilThread, hwnd, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);
    }
    else {
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(_T("Failed to create thread.")));
        // Re-enable buttons and reset status
        EnableWindow(hCreateVeilButton, TRUE);
        EnableWindow(hExtractVeilButton, TRUE);
        EnableWindow(hCreateSVeilButton, TRUE);
        EnableWindow(hExtractSVeilButton, TRUE);
        SetWindowText(hStatusText, _T(""));
        // Reset and hide the progress bar
        SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
        ShowWindow(hProgressBar, SW_HIDE);
    }
}

DWORD WINAPI CreateVeilThread(LPVOID param) {
    HWND hwnd = (HWND)param;
    TCHAR png_path[MAX_PATH];
    TCHAR hidden_file_path[MAX_PATH];
    TCHAR password[256];
    TCHAR output_file[MAX_PATH];

    GetWindowText(hPngPathEdit, png_path, MAX_PATH);
    GetWindowText(hHiddenFileEdit, hidden_file_path, MAX_PATH);
    GetWindowText(hPasswordEdit, password, 256);

    if (_tcslen(png_path) == 0 || _tcslen(hidden_file_path) == 0 || _tcslen(password) == 0) {
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(_T("Please fill in all fields.")));
        goto cleanup;
    }

    if (!IsPasswordStrong(password)) {
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(_T("Password is too weak. It must be at least 8 characters long and include uppercase, lowercase, digits, and special characters.")));
        goto cleanup;
    }

    // Ask user for output file
    if (!SaveFileDialog(hwnd, output_file, MAX_PATH, _T("PNG Files\0*.png\0All Files\0*.*\0"))) {
        // User canceled or an error occurred
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(_T("Operation canceled.")));
        goto cleanup;
    }

    // Update progress bar
    SendMessage(hProgressBar, PBM_SETPOS, 50, 0);
    PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(_T("Embedding data...")));

    if (embed_data_in_png(png_path, hidden_file_path, output_file, password) == 0) {
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(_T("Veil created successfully!")));
        ClearInputFields();  // Clear the input fields
    }
    else {
        const TCHAR* error_message = get_last_error_message();
        if (error_message == NULL || _tcslen(error_message) == 0) {
            error_message = _T("An error occurred during embedding.");
        }
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(error_message));
    }

cleanup:
    // Securely erase the password from memory
    SecureZeroMemory(password, sizeof(password));

    // Re-enable buttons and reset status
    EnableWindow(hCreateVeilButton, TRUE);
    EnableWindow(hExtractVeilButton, TRUE);
    EnableWindow(hCreateSVeilButton, TRUE);
    EnableWindow(hExtractSVeilButton, TRUE);

    // Reset and hide the progress bar
    SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
    ShowWindow(hProgressBar, SW_HIDE);

    return 0;
}

void ExtractVeil(HWND hwnd) {
    // Disable buttons
    EnableWindow(hCreateVeilButton, FALSE);
    EnableWindow(hExtractVeilButton, FALSE);
    EnableWindow(hCreateSVeilButton, FALSE);
    EnableWindow(hExtractSVeilButton, FALSE);

    // Show and reset progress bar
    SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
    ShowWindow(hProgressBar, SW_SHOW);

    SetWindowText(hStatusText, _T("Extracting veil..."));

    // Create a thread to perform the operation
    HANDLE hThread = CreateThread(NULL, 0, ExtractVeilThread, hwnd, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);
    }
    else {
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(_T("Failed to create thread.")));
        // Re-enable buttons and reset status
        EnableWindow(hCreateVeilButton, TRUE);
        EnableWindow(hExtractVeilButton, TRUE);
        EnableWindow(hCreateSVeilButton, TRUE);
        EnableWindow(hExtractSVeilButton, TRUE);
        SetWindowText(hStatusText, _T(""));
        // Reset and hide the progress bar
        SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
        ShowWindow(hProgressBar, SW_HIDE);
    }
}

DWORD WINAPI ExtractVeilThread(LPVOID param) {
    HWND hwnd = (HWND)param;
    TCHAR png_path[MAX_PATH];
    TCHAR password[256];
    TCHAR output_folder[MAX_PATH];
    TCHAR extracted_file_name[MAX_PATH];

    GetWindowText(hPngPathEdit, png_path, MAX_PATH);
    GetWindowText(hPasswordEdit, password, 256);

    if (_tcslen(png_path) == 0 || _tcslen(password) == 0) {
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(_T("Please fill in PNG File and Password.")));
        goto cleanup;
    }

    // Ask user for output folder
    if (!SelectFolderDialog(hwnd, output_folder, MAX_PATH)) {
        // User canceled or an error occurred
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(_T("Operation canceled.")));
        goto cleanup;
    }

    // Update progress bar
    SendMessage(hProgressBar, PBM_SETPOS, 50, 0);
    PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(_T("Extracting data...")));

    if (extract_data_from_png(png_path, output_folder, password, extracted_file_name) == 0) {
        // Extract only the file name
        TCHAR* fileNameOnly = extracted_file_name;
        TCHAR* lastBackslash = _tcsrchr(extracted_file_name, _T('\\'));
        if (lastBackslash != NULL) {
            fileNameOnly = lastBackslash + 1;
        }
        TCHAR message[512];
        _stprintf_s(message, 512, _T("Veiled '%s' was extracted successfully!"), fileNameOnly);
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(message));
        ClearInputFields();  // Clear the input fields
    }
    else {
        const TCHAR* error_message = get_last_error_message();
        if (error_message == NULL || _tcslen(error_message) == 0) {
            error_message = _T("An error occurred during extraction.");
        }
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(error_message));
    }

cleanup:
    // Securely erase the password from memory
    SecureZeroMemory(password, sizeof(password));

    // Re-enable buttons and reset status
    EnableWindow(hCreateVeilButton, TRUE);
    EnableWindow(hExtractVeilButton, TRUE);
    EnableWindow(hCreateSVeilButton, TRUE);
    EnableWindow(hExtractSVeilButton, TRUE);

    // Reset and hide the progress bar
    SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
    ShowWindow(hProgressBar, SW_HIDE);

    return 0;
}

void CreateSVeil(HWND hwnd) {
    // Disable buttons
    EnableWindow(hCreateVeilButton, FALSE);
    EnableWindow(hExtractVeilButton, FALSE);
    EnableWindow(hCreateSVeilButton, FALSE);
    EnableWindow(hExtractSVeilButton, FALSE);

    // Show and reset progress bar
    SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
    ShowWindow(hProgressBar, SW_SHOW);

    SetWindowText(hStatusText, _T("Creating sVeil..."));

    // Create a thread to perform the operation
    HANDLE hThread = CreateThread(NULL, 0, CreateSVeilThread, hwnd, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);
    }
    else {
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(_T("Failed to create thread.")));
        // Re-enable buttons and reset status
        EnableWindow(hCreateVeilButton, TRUE);
        EnableWindow(hExtractVeilButton, TRUE);
        EnableWindow(hCreateSVeilButton, TRUE);
        EnableWindow(hExtractSVeilButton, TRUE);
        SetWindowText(hStatusText, _T(""));
        // Reset and hide the progress bar
        SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
        ShowWindow(hProgressBar, SW_HIDE);
    }
}

DWORD WINAPI CreateSVeilThread(LPVOID param) {
    HWND hwnd = (HWND)param;
    TCHAR png_path[MAX_PATH];
    TCHAR hidden_file_path[MAX_PATH];
    TCHAR password[256];
    TCHAR output_file[MAX_PATH];

    GetWindowText(hPngPathEdit, png_path, MAX_PATH);
    GetWindowText(hHiddenFileEdit, hidden_file_path, MAX_PATH);
    GetWindowText(hPasswordEdit, password, 256);

    if (_tcslen(png_path) == 0 || _tcslen(hidden_file_path) == 0 || _tcslen(password) == 0) {
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(_T("Please fill in all fields.")));
        goto cleanup;
    }

    if (!IsPasswordStrong(password)) {
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(_T("Password is too weak. It must be at least 8 characters long and include uppercase, lowercase, digits, and special characters.")));
        goto cleanup;
    }

    // Ask user for output file
    if (!SaveFileDialog(hwnd, output_file, MAX_PATH, _T("PNG Files\0*.png\0All Files\0*.*\0"))) {
        // User canceled or an error occurred
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(_T("Operation canceled.")));
        goto cleanup;
    }

    // Update progress bar
    SendMessage(hProgressBar, PBM_SETPOS, 50, 0);
    PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(_T("Embedding data...")));

    // Use sVeil embedding function
    if (sveil_embed_data_in_png(png_path, hidden_file_path, output_file, password) == 0) {
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(_T("sVeil created successfully!")));
        ClearInputFields();  // Clear the input fields
    }
    else {
        const TCHAR* error_message = get_sveil_error_message();
        if (error_message == NULL || _tcslen(error_message) == 0) {
            error_message = _T("An error occurred during embedding.");
        }
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(error_message));
    }

cleanup:
    // Securely erase the password from memory
    SecureZeroMemory(password, sizeof(password));

    // Re-enable buttons and reset status
    EnableWindow(hCreateVeilButton, TRUE);
    EnableWindow(hExtractVeilButton, TRUE);
    EnableWindow(hCreateSVeilButton, TRUE);
    EnableWindow(hExtractSVeilButton, TRUE);

    // Reset and hide the progress bar
    SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
    ShowWindow(hProgressBar, SW_HIDE);

    return 0;
}

void ExtractSVeil(HWND hwnd) {
    // Disable buttons
    EnableWindow(hCreateVeilButton, FALSE);
    EnableWindow(hExtractVeilButton, FALSE);
    EnableWindow(hCreateSVeilButton, FALSE);
    EnableWindow(hExtractSVeilButton, FALSE);

    // Show and reset progress bar
    SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
    ShowWindow(hProgressBar, SW_SHOW);

    SetWindowText(hStatusText, _T("Extracting sVeil..."));

    // Create a thread to perform the operation
    HANDLE hThread = CreateThread(NULL, 0, ExtractSVeilThread, hwnd, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);
    }
    else {
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(_T("Failed to create thread.")));
        // Re-enable buttons and reset status
        EnableWindow(hCreateVeilButton, TRUE);
        EnableWindow(hExtractVeilButton, TRUE);
        EnableWindow(hCreateSVeilButton, TRUE);
        EnableWindow(hExtractSVeilButton, TRUE);
        SetWindowText(hStatusText, _T(""));
        // Reset and hide the progress bar
        SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
        ShowWindow(hProgressBar, SW_HIDE);
    }
}

DWORD WINAPI ExtractSVeilThread(LPVOID param) {
    HWND hwnd = (HWND)param;
    TCHAR png_path[MAX_PATH];
    TCHAR password[256];
    TCHAR output_folder[MAX_PATH];
    TCHAR extracted_file_name[MAX_PATH];

    GetWindowText(hPngPathEdit, png_path, MAX_PATH);
    GetWindowText(hPasswordEdit, password, 256);

    if (_tcslen(png_path) == 0 || _tcslen(password) == 0) {
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(_T("Please fill in PNG File and Password.")));
        goto cleanup;
    }

    // Ask user for output folder
    if (!SelectFolderDialog(hwnd, output_folder, MAX_PATH)) {
        // User canceled or an error occurred
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(_T("Operation canceled.")));
        goto cleanup;
    }

    // Update progress bar
    SendMessage(hProgressBar, PBM_SETPOS, 50, 0);
    PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(_T("Extracting data...")));

    // Use sVeil extraction function
    if (sveil_extract_data_from_png(png_path, output_folder, password, extracted_file_name) == 0) {
        // Extract only the file name
        TCHAR* fileNameOnly = extracted_file_name;
        TCHAR* lastBackslash = _tcsrchr(extracted_file_name, _T('\\'));
        if (lastBackslash != NULL) {
            fileNameOnly = lastBackslash + 1;
        }
        TCHAR message[512];
        _stprintf_s(message, 512, _T("sVeil '%s' was extracted successfully!"), fileNameOnly);
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(message));
        ClearInputFields();  // Clear the input fields
    }
    else {
        const TCHAR* error_message = get_sveil_error_message();
        if (error_message == NULL || _tcslen(error_message) == 0) {
            error_message = _T("An error occurred during extraction.");
        }
        PostMessage(hwnd, WM_UPDATE_STATUS_TEXT, 0, (LPARAM)_tcsdup(error_message));
    }

cleanup:
    // Securely erase the password from memory
    SecureZeroMemory(password, sizeof(password));

    // Re-enable buttons and reset status
    EnableWindow(hCreateVeilButton, TRUE);
    EnableWindow(hExtractVeilButton, TRUE);
    EnableWindow(hCreateSVeilButton, TRUE);
    EnableWindow(hExtractSVeilButton, TRUE);

    // Reset and hide the progress bar
    SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
    ShowWindow(hProgressBar, SW_HIDE);

    return 0;
}

BOOL OpenFileDialog(HWND hwnd, LPTSTR fileName, DWORD fileNameSize, LPCTSTR filter) {
    OPENFILENAME ofn;
    ZeroMemory(&ofn, sizeof(ofn));

    fileName[0] = _T('\0');

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = fileNameSize;
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST;

    return GetOpenFileName(&ofn);
}

BOOL SaveFileDialog(HWND hwnd, LPTSTR fileName, DWORD fileNameSize, LPCTSTR filter) {
    OPENFILENAME ofn;
    ZeroMemory(&ofn, sizeof(ofn));

    fileName[0] = _T('\0');

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = filter;
    ofn.lpstrDefExt = _T("png");
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = fileNameSize;
    ofn.Flags = OFN_EXPLORER | OFN_OVERWRITEPROMPT;

    return GetSaveFileName(&ofn);
}

BOOL SelectFolderDialog(HWND hwnd, LPTSTR folderPath, DWORD folderPathSize) {
    BROWSEINFO bi = { 0 };
    bi.lpszTitle = _T("Select Output Folder");
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_USENEWUI;
    bi.hwndOwner = hwnd;

    LPITEMIDLIST pidl = SHBrowseForFolder(&bi);
    if (pidl != 0) {
        BOOL result = SHGetPathFromIDList(pidl, folderPath);
        CoTaskMemFree(pidl);
        return result;
    }
    return FALSE;
}

void ClearInputFields() {
    SetWindowText(hPngPathEdit, _T(""));
    SetWindowText(hHiddenFileEdit, _T(""));
    SetWindowText(hPasswordEdit, _T(""));
    SendMessage(hShowPasswordCheckbox, BM_SETCHECK, BST_UNCHECKED, 0);
    SendMessage(hPasswordEdit, EM_SETPASSWORDCHAR, (WPARAM)'*', 0);
    InvalidateRect(hPasswordEdit, NULL, TRUE);
}

BOOL IsPasswordStrong(const TCHAR* password) {
    size_t length = _tcslen(password);
    if (length < 8) return FALSE;

    BOOL hasUpper = FALSE, hasLower = FALSE, hasDigit = FALSE, hasSpecial = FALSE;

    for (size_t i = 0; i < length; i++) {
        if (_istupper(password[i])) hasUpper = TRUE;
        else if (_istlower(password[i])) hasLower = TRUE;
        else if (_istdigit(password[i])) hasDigit = TRUE;
        else hasSpecial = TRUE;
    }

    return hasUpper && hasLower && hasDigit && hasSpecial;
}

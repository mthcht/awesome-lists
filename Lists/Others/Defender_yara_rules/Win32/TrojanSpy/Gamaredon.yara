rule TrojanSpy_Win32_Gamaredon_MA_2147762078_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gamaredon.MA!MTB"
        threat_id = "2147762078"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamaredon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "InstallPath=\"%APPDATA%\\\\TN\"" ascii //weight: 1
        $x_1_2 = "RunProgram=\"hidcon:nowait:cmd /c document.doc\"" ascii //weight: 1
        $x_1_3 = "RunProgram=\"hidcon:wget --no-check-certificate https://nodejs.org/dist/latest-carbon/win-x86/node.exe\"" ascii //weight: 1
        $x_1_4 = "RunProgram=\"hidcon:wget --no-check-certificate https://www.torproject.org/dist/torbrowser/9.5.1/tor-win32-0.4.3.5.zip\"" ascii //weight: 1
        $x_1_5 = "RunProgram=\"hidcon:7za e -y tor-win32-0.4.3.5.zip\"" ascii //weight: 1
        $x_1_6 = {52 00 75 00 6e 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 3d 00 22 00 68 00 69 00 64 00 63 00 6f 00 6e 00 3a 00 6e 00 6f 00 77 00 61 00 69 00 74 00 3a 00 63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 69 00 66 00 20 00 6e 00 6f 00 74 00 20 00 65 00 78 00 69 00 73 00 74 00 20 00 68 00 6f 00 73 00 74 00 6e 00 61 00 6d 00 65 00 20 00 28 00 6e 00 6f 00 64 00 65 00 20 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 ?? ?? ?? 2e 00 ?? ?? ?? 2e 00 ?? ?? ?? 2e 00 ?? ?? ?? 29 00 22 00}  //weight: 1, accuracy: Low
        $x_1_7 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 6e 6f 77 61 69 74 3a 63 6d 64 20 2f 63 20 69 66 20 6e 6f 74 20 65 78 69 73 74 20 68 6f 73 74 6e 61 6d 65 20 28 6e 6f 64 65 20 73 65 72 76 69 63 65 20 ?? ?? ?? 2e ?? ?? ?? 2e ?? ?? ?? 2e ?? ?? ?? 29 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


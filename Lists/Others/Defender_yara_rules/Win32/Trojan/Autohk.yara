rule Trojan_Win32_Autohk_MA_2147808970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autohk.MA!MTB"
        threat_id = "2147808970"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autohk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 66 89 0d b8 6c 4c 00 be 2c b0 4a 00 bb 01 00 00 00 89 35 c0 6e 4c 00 c6 44 24 34 00 c6 44 24 2e 00 89 5c 24 30 39 1d c4 41 4c 00 0f 8e ?? ?? ?? ?? 80 7c 24 2e 00 a1 cc 41 4c 00 8b 3c 98 0f 84 ?? ?? ?? ?? 8b 4c 24 30 51 8d 54 24 44 68 a8 08 4a 00 52 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "oxbvWqbSt" ascii //weight: 1
        $x_1_3 = "AutoHotkey" ascii //weight: 1
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
        $x_1_6 = "GetKeyState" ascii //weight: 1
        $x_1_7 = "SetWindowsHookExW" ascii //weight: 1
        $x_1_8 = "NumpadPgDn" wide //weight: 1
        $x_1_9 = "DetectHiddenWindows" wide //weight: 1
        $x_1_10 = "URLDownloadToFile" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


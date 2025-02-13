rule TrojanSpy_Win32_AutoHK_AA_2147750334_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/AutoHK.AA!MSR"
        threat_id = "2147750334"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoHK"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 69 74 65 20 3d 20 68 74 74 70 [0-1] 3a 2f 2f 32 6e 6f 2e 63 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 2c 20 [0-50] 2e 65 78 65 2c 20 [0-14] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {52 75 6e 2c 20 [0-14] 2e 65 78 65 2c 2c 20 55 73 65 45 72 72 6f 72 4c 65 76 65 6c}  //weight: 1, accuracy: Low
        $x_1_4 = "AutoHotkey.exe" wide //weight: 1
        $x_1_5 = "WindowSpy.ahk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


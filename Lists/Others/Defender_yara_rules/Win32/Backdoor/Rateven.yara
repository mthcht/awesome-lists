rule Backdoor_Win32_Rateven_A_2147641119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rateven.A"
        threat_id = "2147641119"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rateven"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 59 53 5f 50 41 54 48 3a 20 20 22 00}  //weight: 1, accuracy: High
        $x_1_2 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00}  //weight: 1, accuracy: High
        $x_1_3 = "ShellExecute=RunDll32.exe ntlog.dll," ascii //weight: 1
        $x_1_4 = {83 3b 00 0f 85 ?? ?? ?? ?? 68 ?? ?? 40 00 e8 ?? fe ff ff 89 03 83 3b 00 0f 84 ?? ?? ?? ?? 68 ?? ?? 40 00 8b 03 50 e8 ?? fe ff ff a3 ?? ?? 40 00 68 ?? ?? 40 00 8b 03 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


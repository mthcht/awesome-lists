rule Backdoor_Win32_Minjat_A_2147660183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Minjat.A"
        threat_id = "2147660183"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Minjat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 41 54 41 5f 42 45 47 49 4e 3a 00}  //weight: 1, accuracy: High
        $x_1_2 = "System32\\DRIVERS\\asyncmac.sys" ascii //weight: 1
        $x_1_3 = "\"%s\" -local" wide //weight: 1
        $x_1_4 = "%USERPROFILE%\\spoolv.exe" wide //weight: 1
        $x_1_5 = "Winsta0\\Default" wide //weight: 1
        $x_1_6 = {8a 04 3e 3c 30 72 0c 3c 39 77 08 0f b6 c8 83 e9 30 eb 16 3c 61 72 0c 3c 7a 77 08 0f b6 c8 83 e9 57 eb 06 0f b6 c8 83 e9 37}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


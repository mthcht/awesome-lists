rule Trojan_Win32_Simeda_A_2147680109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Simeda.A"
        threat_id = "2147680109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Simeda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 4c 53 56 57 b9 05 00 00 00 be ?? ?? ?? ?? 8d 7d ec f3 a5 a1 ?? ?? ?? ?? 89 45 dc 8b 0d ?? ?? ?? ?? 89 4d e0 8b 15 ?? ?? ?? ?? 89 55 e4 a0 ?? ?? ?? ?? 88 45 e8 8d 4d ec 51 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "Natiaonal Safe Meadi" ascii //weight: 1
        $x_1_3 = "taskkill /f /im rundll32.exe" ascii //weight: 1
        $x_1_4 = "aPPLICATIONS\\IEXPLORE.EXE\\SHELL\\OPEN\\COMMAND" ascii //weight: 1
        $x_1_5 = {4e 65 74 42 6f 74 5f 41 74 74 61 63 6b [0-4] 5c 53 65 72 76 65 72 5c 73 76 63 68 6f 73 74 5c 52 65 6c 65 61 73 65 5c 33 36 35 43 6b 6a 78 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


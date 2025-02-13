rule Backdoor_Win32_Portless_A_2147616280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Portless.gen!A"
        threat_id = "2147616280"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Portless"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {25 01 00 00 80 79 05 48 83 c8 fe 40 8a 04 0a 74 04 34 ?? eb 02 34 ?? 88 01 46 41 3b f7 7c df}  //weight: 10, accuracy: Low
        $x_2_2 = {66 83 38 50 0f 85 ?? ?? 00 00 8b c8 66 83 79 02 45 0f 85 ?? ?? 00 00 8b d0 66 83 7a 04 52 0f 85 ?? ?? 00 00 66 83 78 06 46 0f 85 ?? ?? 00 00}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 44 24 0c 85 c0 76 46 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? c6 80 ?? ?? ?? ?? 00 e8 ?? ?? 00 00 8b 4c 24 18 8b 15 ?? ?? ?? ?? 83 c4 0c 6a 00 51 68 ?? ?? ?? ?? 52 e8 ?? ?? 00 00 83 f8 ff 74 3e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}


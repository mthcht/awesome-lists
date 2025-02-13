rule Trojan_Win32_PanPals_2147811718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PanPals.gen!dha"
        threat_id = "2147811718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PanPals"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 47 04 03 c3 8a 84 08 08 02 00 00 88 04 0e 41 3b 0f 72 ec}  //weight: 5, accuracy: High
        $x_5_2 = {6a 40 68 00 30 00 00 ff 36 50 ff 95 ?? ?? ?? ?? 8b 4e 04 ff 36 81 c1 08 02 00 00 [0-6] 03 cf 51 50 e8}  //weight: 5, accuracy: Low
        $x_5_3 = {6a 04 68 00 30 00 00 8b 55 ?? 8b 02 05 c0 0d 00 00 50 6a 00 ff ?? ?? ?? ?? ?? 89 45 ?? 8b 4d ?? 81 c1 a0 0b 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


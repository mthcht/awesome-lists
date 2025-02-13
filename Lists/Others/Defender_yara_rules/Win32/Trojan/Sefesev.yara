rule Trojan_Win32_Sefesev_A_2147672252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sefesev.A"
        threat_id = "2147672252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sefesev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 61 66 78 2e 65 78 65 00 5c 73 76 63 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a 47 01 47 84 c0 75 f8 a1 ?? ?? 40 00 8b 0d ?? ?? 40 00 6a 00 89 07 68 ?? ?? 40 00 89 4f 04 ff 15 ?? ?? 40 00 8b 15 ?? ?? 40 00 68 00 52 03 00 81 c2 75 0f 00 00 8b f0 52 56 ff 15 ?? ?? 40 00 56 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 68 e8 03 00 00 ff 15 ?? ?? 40 00 6a 00 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 08 40 84 c9 75 f9 56 57 2b c2 bf ?? ?? 40 00 88 88 ?? ?? 40 00 4f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


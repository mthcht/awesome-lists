rule Trojan_Win32_Lampa_A_2147650879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lampa.A"
        threat_id = "2147650879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lampa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 8a 00 30 01 8b 0d ?? ?? ?? ?? 41 81 f9 ae 01 00 00 89 0d 00 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 09 8a 09 30 08 a1 ?? ?? ?? ?? 40 3d ae 01 00 00 a3 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 40 68 00 02 00 00 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 2d 00 50 0f 00 a3 ?? ?? ?? ?? 79 0c a1 ?? ?? ?? ?? a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


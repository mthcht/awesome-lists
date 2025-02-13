rule Trojan_Win32_Lodpois_B_2147687968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lodpois.B"
        threat_id = "2147687968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lodpois"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {85 c0 74 0b 8b d8 ff d3 6a ff e8 ?? ?? ?? ?? 6a 00 e8}  //weight: 10, accuracy: Low
        $x_5_2 = {43 6f 6e 73 6f 6c 65 00 43 6f 64 65 00 00 00 00 55 8b ec 83 c4 f4 53 33 c9 89 4d f4 89 55 f8 89 45 fc 8b 45 fc e8}  //weight: 5, accuracy: High
        $x_5_3 = {43 6f 6d 6d 46 75 6e 63 2e 64 6c 6c 00 47 65 74 49 6e 73 74 50 61 74 68 00 48 69 64 65 45 78 65 63 75 74 65 00 49 73 57 6f 77 36 34 00}  //weight: 5, accuracy: High
        $x_5_4 = {4d 6f 64 75 6f 65 20 46 69 6c 65 20 50 61 74 68 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


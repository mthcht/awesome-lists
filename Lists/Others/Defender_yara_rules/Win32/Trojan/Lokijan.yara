rule Trojan_Win32_Lokijan_A_2147818120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lokijan.A"
        threat_id = "2147818120"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lokijan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 8b 55 0c 81 31 ?? ?? ?? ?? f7 11 83 c1 04 4a 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 0c 41 33 d2 f7 f1 92 3b 45 08}  //weight: 1, accuracy: High
        $x_2_3 = {33 c0 40 c1 e0 06 8d 40 f0 64 8b 00}  //weight: 2, accuracy: High
        $x_2_4 = {68 00 1a 40 00 e8 ?? ?? ff ff a3 ?? ?? 40 00 6a ?? 68 ?? 1a 40 00 e8 ?? ?? ff ff a3 ?? ?? 40 00 6a ?? 68 ?? 1a 40 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


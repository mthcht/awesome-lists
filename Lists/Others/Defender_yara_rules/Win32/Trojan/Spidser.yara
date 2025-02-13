rule Trojan_Win32_Spidser_A_2147627783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spidser.A"
        threat_id = "2147627783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spidser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 20 89 04 8d e8 ba 00 10 8d 94 ?? ?? ?? ?? ?? 52 55 ff 15 ?? ?? ?? ?? 85 c0 [0-32] 81 c4 44 02 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 01 55 55 55 89 04 8d e4 ba 00 10 68 ?? ?? ?? ?? 41 55 55 89 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 2d ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 83 c4 38 89 04 8d e4 ba 00 10 41 89 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


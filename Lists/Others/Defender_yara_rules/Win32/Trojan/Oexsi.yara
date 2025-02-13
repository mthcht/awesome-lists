rule Trojan_Win32_Oexsi_A_2147605727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Oexsi.A"
        threat_id = "2147605727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Oexsi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 6c 10 40 00 50 e8 24 00 00 00 8d 85 fc fe ff ff 68 60 10 40 00 50 e8 13 00 00 00 83 c4 10 8d 85 fc fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {33 c9 39 4c 24 0c 7e 19 8b 44 24 08 56 8b 74 24 08 8a 16 32 d1 88 10 40 46 41 3b 4c 24 10 7c f1 5e}  //weight: 1, accuracy: High
        $x_1_3 = {57 ff d6 59 85 c0 59 75 27 39 45 10 6a 21 74 0a ff 75 0c 68 ?? ?? 40 00 eb 08 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


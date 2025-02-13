rule Trojan_Win32_Brolhorm_A_2147682808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Brolhorm.A"
        threat_id = "2147682808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Brolhorm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 d8 88 1e eb 10 8a 0e 32 c8 0f be 84 24 48 02 00 00 02 c8 88 0e 8b 44 24 10 46 48 89 44 24 10 75 9c}  //weight: 1, accuracy: High
        $x_1_2 = {ff d7 25 ff 01 00 00 89 85 d0 fe ff ff 33 c9 89 8d d4 fe ff ff 3b c8 7d 11 8b d6 c1 e2 06 03 d6 8d 74 56 01 89 75 dc 41 eb e5}  //weight: 1, accuracy: High
        $x_1_3 = {3d 00 04 00 00 73 33 f7 c1 00 00 00 20 74 08 80 8c 05 84 ef ff ff 01 f7 c1 00 00 00 40 74 08 80 8c 05 84 ef ff ff 02 f7 c1 00 00 00 80 74 08 80 8c 05 84 ef ff ff 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


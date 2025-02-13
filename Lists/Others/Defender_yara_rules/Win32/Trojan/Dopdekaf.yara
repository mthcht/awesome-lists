rule Trojan_Win32_Dopdekaf_A_2147828703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dopdekaf.A"
        threat_id = "2147828703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dopdekaf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 0b 03 00 00 95 9e 7e 62 00 00 04 1f 0c 7e 8a 00 00 04 1a 9a 20 82 03 00 00 95 9e 7e 2a 00 00 04 7e 8a 00 00 04 1a 9a 20 f5 03 00 00 95 59}  //weight: 1, accuracy: High
        $x_1_2 = {20 19 02 00 00 95 5a 7e 8a 00 00 04 1a 9a 20 c9 00 00 00 95 58 58 80 2a 00 00 04 38 3d 15 00 00 7e 35 00 00 04 16 32 22 7e 3f 00 00 04 2c 1b 7e 35 00 00 04 7e 3f 00 00 04 8e 69 2f 0d}  //weight: 1, accuracy: High
        $x_1_3 = {1f 3d 8f 0f 00 00 01 25 71 0f 00 00 01 7e 8a 00 00 04 18 9a 20 46 09 00 00 95 61 81 0f 00 00 01 38 75 0b 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {7e 8a 00 00 04 18 9a 20 e1 04 00 00 95 5a 7e 8a 00 00 04 18 9a 20 92 0f 00 00 95 58 59 81 0f 00 00 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


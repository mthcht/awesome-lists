rule Trojan_Win32_Seepeed_A_2147719217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Seepeed.A"
        threat_id = "2147719217"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Seepeed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 0c 18 8b 55 fc c6 04 39 01 0f b6 0c 18 88 04 11 48 79 eb}  //weight: 1, accuracy: High
        $x_1_2 = {88 14 30 8b d1 c1 fa 08 88 54 30 01 88 4c 30 02 83 c0 03 33 c9 33 ff}  //weight: 1, accuracy: High
        $x_1_3 = {8b c1 c1 e8 02 8a 04 38 88 02 83 e1 03 8b c6 c1 e8 04 c1 e1 04 0b c1 8a 04 38 88 42 01}  //weight: 1, accuracy: High
        $x_1_4 = {00 64 6c 6c 2e 64 6c 6c 00 53 76 63 4d 61 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


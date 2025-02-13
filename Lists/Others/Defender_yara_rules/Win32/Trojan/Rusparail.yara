rule Trojan_Win32_Rusparail_A_2147637258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rusparail.A"
        threat_id = "2147637258"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rusparail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 51 51 50 61 73 73 57 6f 72 64 3d 00 3f 51 51 4e 75 6d 62 65 72}  //weight: 1, accuracy: High
        $x_1_2 = {26 70 61 73 73 3d 00 3f 69 64 3d}  //weight: 1, accuracy: High
        $x_3_3 = {42 6f 67 75 73 20 6d 65 73 73 61 67 65 20 63 6f 64 65 20 25 64 00}  //weight: 3, accuracy: High
        $x_3_4 = {33 36 30 30 67 7a 2e 63 6e 2e 63 6e 00}  //weight: 3, accuracy: High
        $x_3_5 = {49 45 58 50 4c 4f 50 45 2e 45 58 45 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}


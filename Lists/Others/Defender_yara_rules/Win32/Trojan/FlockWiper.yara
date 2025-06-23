rule Trojan_Win32_FlockWiper_A_2147944437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlockWiper.A"
        threat_id = "2147944437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlockWiper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 2d 00 2d 00 2d 00 20 00 57 00 6f 00 72 00 6b 00 69 00 6e 00 67 00 20 00 6f 00 6e 00 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 50 00 61 00 72 00 74 00 69 00 74 00 69 00 6f 00 6e 00 73 00 20 00 72 00 65 00 6d 00 6f 00 76 00 65 00 64 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6c 00 6c 00 79 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 00 46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 63 00 6c 00 65 00 61 00 72 00 20 00 70 00 61 00 72 00 74 00 69 00 74 00 69 00 6f 00 6e 00 73 00 3a 00 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 00 46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 77 00 72 00 69 00 74 00 65 00 20 00 74 00 6f 00 20 00 74 00 68 00 65 00 20 00 72 00 65 00 6d 00 61 00 69 00 6e 00 64 00 65 00 72 00 20 00 6f 00 66 00 20 00 74 00 68 00 65 00 20 00 64 00 69 00 73 00 6b 00 3a 00 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 00 46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 67 00 65 00 74 00 20 00 64 00 69 00 73 00 6b 00 20 00 67 00 65 00 6f 00 6d 00 65 00 74 00 72 00 79 00 3a 00 20 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_BlindBaron_A_2147978751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlindBaron.A"
        threat_id = "2147978751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlindBaron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 49 4e 46 4f 5d 20 4e 6f 20 66 69 6c 65 73 20 74 6f 20 75 70 6c 6f 61 64 0a 00}  //weight: 1, accuracy: High
        $x_1_2 = {5b 43 4f 4e 46 49 47 5d 20 6e 61 6d 65 3a 20 25 73 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {4b 52 59 42 49 54 20 43 6c 69 65 6e 74 20 76 25 73 0a 00}  //weight: 1, accuracy: High
        $x_1_4 = {55 50 4c 4f 41 44 20 43 4f 4d 50 4c 45 54 45 21 0a 00}  //weight: 1, accuracy: High
        $x_1_5 = {5b 53 43 41 4e 20 53 54 41 54 53 5d 20 54 69 6d 65 3a 20 25 2e 32 66 20 73 65 63 6f 6e 64 73 20 28 25 2e 30 66 20 6d 73 29 0a 00}  //weight: 1, accuracy: High
        $x_1_6 = {5b 53 43 41 4e 5d 20 53 63 61 6e 6e 69 6e 67 20 64 72 69 76 65 73 2e 2e 2e 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


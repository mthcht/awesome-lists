rule Ransom_Win64_CipherForce_A_2147966705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/CipherForce.A"
        threat_id = "2147966705"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "CipherForce"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 43 49 50 48 45 52 46 4f 52 43 45 00}  //weight: 1, accuracy: High
        $x_1_2 = {5b 00 50 00 47 00 50 00 5f 00 44 00 45 00 42 00 55 00 47 00 5d 00 20 00 42 00 43 00 72 00 79 00 70 00 74 00 20 00 52 00 53 00 41 00 20 00 61 00 6c 00 67 00 6f 00 72 00 69 00 74 00 68 00 6d 00 20 00 70 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00 20 00 6f 00 70 00 65 00 6e 00 65 00 64 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6c 00 6c 00 79 00 0a 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5b 00 50 00 47 00 50 00 5f 00 53 00 55 00 43 00 43 00 45 00 53 00 53 00 5d 00 20 00 45 00 78 00 74 00 72 00 61 00 63 00 74 00 65 00 64 00 20 00 41 00 45 00 53 00 20 00 6b 00 65 00 79 00 20 00 28 00 33 00 32 00 20 00 62 00 79 00 74 00 65 00 73 00 29 00 20 00 61 00 6e 00 64 00 20 00 49 00 56 00 20 00 28 00 31 00 36 00 20 00 62 00 79 00 74 00 65 00 73 00 29 00 0a 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 20 00 42 00 6c 00 6f 00 63 00 6b 00 20 00 53 00 69 00 7a 00 65 00 3a 00 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {50 00 72 00 6f 00 63 00 65 00 73 00 73 00 69 00 6e 00 67 00 20 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 20 00 64 00 72 00 69 00 76 00 65 00 3a 00 20 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


rule Ransom_Win64_Vect_A_2147966135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Vect.A"
        threat_id = "2147966135"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Vect"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 45 43 54 20 4c 4f 43 4b 45 52 0a 0a 00}  //weight: 1, accuracy: High
        $x_1_2 = {59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 00}  //weight: 1, accuracy: High
        $x_1_3 = {4d 6f 75 6e 74 69 6e 67 20 6e 65 74 77 6f 72 6b 20 64 72 69 76 65 73 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_4 = {45 6e 75 6d 65 72 61 74 69 6e 67 20 53 4d 42 20 73 68 61 72 65 73 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_5 = {50 73 45 78 65 63 2d 73 74 79 6c 65 20 73 70 72 65 61 64 20 73 74 61 72 74 69 6e 67 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_6 = {47 50 4f 20 64 65 70 6c 6f 79 20 76 69 61 20 57 4d 49 20 73 74 61 72 74 69 6e 67 2e 2e 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win64_Vect_B_2147966606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Vect.B"
        threat_id = "2147966606"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Vect"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 45 43 54 20 32 2e 30 0a 00}  //weight: 1, accuracy: High
        $x_1_2 = {5b 53 63 61 6e 6e 65 72 5d 20 53 63 61 6e 6e 65 64 20 25 64 20 70 61 74 68 73 2c 20 71 75 65 75 65 64 20 25 64 20 66 69 6c 65 73 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {5b 2a 5d 20 53 74 61 72 74 69 6e 67 20 25 7a 75 20 73 63 61 6e 6e 65 72 20 74 68 72 65 61 64 73 20 61 6e 64 20 25 7a 75 20 65 6e 63 72 79 70 74 6f 72 20 74 68 72 65 61 64 73 0a 00}  //weight: 1, accuracy: High
        $x_1_4 = {5b 2a 5d 20 45 6e 63 72 79 70 74 6f 72 73 20 63 6f 6d 70 6c 65 74 65 2e 0a 00}  //weight: 1, accuracy: High
        $x_1_5 = {5b 2a 5d 20 46 69 6c 65 73 20 65 6e 63 72 79 70 74 65 64 3a 20 25 7a 75 0d 00}  //weight: 1, accuracy: High
        $x_1_6 = {5b 2b 5d 20 43 68 65 63 6b 20 21 21 21 5f 52 45 41 44 5f 4d 45 5f 21 21 21 2e 74 78 74 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


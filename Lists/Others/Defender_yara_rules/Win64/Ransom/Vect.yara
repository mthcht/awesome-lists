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


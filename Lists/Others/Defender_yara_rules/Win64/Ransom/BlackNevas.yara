rule Ransom_Win64_BlackNevas_A_2147959522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BlackNevas.A"
        threat_id = "2147959522"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackNevas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 00 72 00 65 00 73 00 73 00 20 00 65 00 6e 00 74 00 65 00 72 00 20 00 74 00 6f 00 20 00 63 00 6f 00 6e 00 74 00 69 00 6e 00 75 00 65 00 2e 00 2e 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {47 00 65 00 6e 00 65 00 72 00 61 00 74 00 65 00 20 00 72 00 61 00 6e 00 64 00 6f 00 6d 00 69 00 7a 00 65 00 72 00 20 00 6e 00 6f 00 69 00 63 00 65 00 2e 00 20 00 50 00 6c 00 65 00 61 00 73 00 65 00 20 00 61 00 77 00 61 00 69 00 74 00 20 00 31 00 35 00 20 00 73 00 65 00 63 00 6f 00 6e 00 64 00 73 00 2e 00 2e 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {54 00 72 00 79 00 20 00 74 00 6f 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 20 00 66 00 6f 00 6c 00 64 00 65 00 72 00 3a 00 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 20 00 63 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 64 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {43 00 72 00 65 00 61 00 74 00 65 00 20 00 57 00 53 00 41 00 20 00 63 00 6f 00 6e 00 6e 00 65 00 74 00 69 00 6f 00 6e 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "ERROR: /debug option can't be used without /p option. Process terminated." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


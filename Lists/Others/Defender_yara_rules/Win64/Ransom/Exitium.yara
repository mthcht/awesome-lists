rule Ransom_Win64_Exitium_A_2147968379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Exitium.A"
        threat_id = "2147968379"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Exitium"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 00 61 00 79 00 6c 00 6f 00 61 00 64 00 20 00 44 00 65 00 70 00 6c 00 6f 00 79 00 20 00 50 00 6f 00 6c 00 69 00 63 00 79 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {59 00 4f 00 55 00 20 00 41 00 52 00 45 00 20 00 55 00 4e 00 44 00 45 00 52 00 20 00 41 00 54 00 54 00 41 00 43 00 4b 00 21 00 2e 00 68 00 74 00 6d 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {59 6f 75 20 63 61 6e 20 64 6f 77 6e 6c 6f 61 64 20 71 54 6f 78 20 63 6c 69 65 6e 74 20 66 6f 72 20 77 69 6e 64 6f 77 73 2f 6c 69 6e 75 78 20 66 72 6f 6d 20 67 69 74 68 75 62 2c 20 67 6f 6f 67 6c 65 20 69 74 2e 00}  //weight: 1, accuracy: High
        $x_1_4 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 45 00 78 00 73 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Ransom_Win64_Underground_A_2147954279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Underground.A"
        threat_id = "2147954279"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Underground"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "The Underground team welcomes you!" ascii //weight: 10
        $x_5_2 = "!!readme!!!.txt" wide //weight: 5
        $x_5_3 = "!!READ_ME!!.txt" wide //weight: 5
        $x_1_4 = {5b 25 64 5d 20 68 61 6e 64 6c 65 20 65 78 74 72 61 20 62 79 74 65 73 20 66 6f 72 20 63 65 6e 74 72 61 6c 20 64 69 72 65 63 74 6f 72 79 20 61 74 20 65 6e 64 20 6f 66 20 66 69 6c 65 0a 00}  //weight: 1, accuracy: High
        $x_1_5 = {5b 25 64 5d 20 65 78 74 72 61 20 62 79 74 65 73 20 6f 66 66 73 65 74 20 69 73 3a 20 25 6c 6c 64 2c 20 63 75 72 72 65 6e 74 20 6f 66 66 73 65 74 20 69 73 3a 25 6c 6c 64 0a 00}  //weight: 1, accuracy: High
        $x_1_6 = {5b 25 64 5d 20 65 78 74 72 61 20 6f 66 66 73 65 74 20 61 72 69 73 65 64 20 75 70 20 74 6f 2c 20 72 70 3a 25 6c 6c 64 2c 20 77 70 3a 25 6c 6c 64 2c 20 65 78 74 72 61 3a 25 6c 6c 64 0a 00}  //weight: 1, accuracy: High
        $x_1_7 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {73 00 74 00 6f 00 70 00 20 00 4d 00 53 00 53 00 51 00 4c 00 53 00 45 00 52 00 56 00 45 00 52 00 20 00 2f 00 66 00 20 00 2f 00 6d 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {73 00 74 00 6f 00 70 00 20 00 53 00 51 00 4c 00 53 00 45 00 52 00 56 00 45 00 52 00 41 00 47 00 45 00 4e 00 54 00 20 00 2f 00 66 00 20 00 2f 00 6d 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}


rule Backdoor_Win64_Escad_AA_2147707535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Escad.AA!dha"
        threat_id = "2147707535"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 4b 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 48 00 61 00 63 00 6b 00 65 00 72 00 32 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 6b 70 68 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {7a 61 77 71 2e 62 61 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Escad_F_2147707753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Escad.F!dha"
        threat_id = "2147707753"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Escad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 62 6e 64 6f 65 33 30 64 2d 33 32 64 73 2d 78 65 33 32 2d 33 30 31 64 2d 76 6b 64 6b 33 30 34 39 31 64 32 7a 00}  //weight: 2, accuracy: High
        $x_1_2 = {00 5b 25 30 32 64 2f 25 30 32 64 2f 25 30 32 64 2c 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 5d 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 5f 63 61 70 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 5f 64 6c 75 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 5f 67 6f 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 5f 70 72 63 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 5f 70 75 74 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 5f 71 75 69 74 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 70 65 72 2d 6d 61 63 68 69 6e 65 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 70 65 72 2d 75 73 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}


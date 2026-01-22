rule Backdoor_Win64_EggStremeAgent_C_2147958687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/EggStremeAgent.C!dha"
        threat_id = "2147958687"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "EggStremeAgent"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 2a 5d 20 25 2d 31 36 73 25 64 20 20 6f 70 65 6e 0a 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 6f 6e 6e 65 63 74 49 64 20 3a 20 25 73 20 72 65 61 64 79 20 73 65 6e 64 20 73 69 7a 65 3a 25 64 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {57 69 6e 25 64 2e 25 64 20 25 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {25 73 5c 23 23 23 25 73 23 23 23 25 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {25 64 23 23 23 25 64 23 23 23 25 73 23 23 23 25 73 23 23 23 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win64_EggStremeAgent_D_2147961581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/EggStremeAgent.D!dha"
        threat_id = "2147961581"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "EggStremeAgent"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5b 2a 5d 20 25 2d 31 36 73 25 64 20 20 6f 70 65 6e 0a 00}  //weight: 3, accuracy: High
        $x_3_2 = {63 6f 6e 6e 65 63 74 49 64 20 3a 20 25 73 20 72 65 61 64 79 20 73 65 6e 64 20 73 69 7a 65 3a 25 64 0a 00}  //weight: 3, accuracy: High
        $x_3_3 = {57 69 6e 25 64 2e 25 64 20 25 64 00}  //weight: 3, accuracy: High
        $x_3_4 = {25 73 5c 23 23 23 25 73 23 23 23 25 73 00}  //weight: 3, accuracy: High
        $x_3_5 = {25 64 23 23 23 25 64 23 23 23 25 73 23 23 23 25 73 23 23 23 25 73 00}  //weight: 3, accuracy: High
        $x_6_6 = {23 23 23 33 30 23 23 23 [0-22] 23 23 23 34 34 33}  //weight: 6, accuracy: Low
        $x_6_7 = ".com###443" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 4 of ($x_3_*))) or
            ((2 of ($x_6_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}


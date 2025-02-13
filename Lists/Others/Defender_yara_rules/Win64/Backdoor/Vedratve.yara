rule Backdoor_Win64_Vedratve_A_2147725627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Vedratve.A!dha"
        threat_id = "2147725627"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Vedratve"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {74 65 81 38 44 22 33 11 75 54 83 78 04 01 48 8b c8 75 36}  //weight: 8, accuracy: High
        $x_2_2 = {48 89 8c 24 70 02 00 00 85 ff 74 3d 8b 56 08 48 83 64 24 20 00 4c 8d 84 24 70 02 00 00 48 03 d0 4d 8b cc 48 8b cb ff 15}  //weight: 2, accuracy: High
        $x_1_3 = {80 7c 19 ed 33 75 37 80 7c 19 ee c0 75 30 80 7c 19 ef 48 75 29}  //weight: 1, accuracy: High
        $x_1_4 = {80 7c 19 f0 8d 75 22 80 7c 19 f1 0d 75 1b 80 7c 19 f6 c7}  //weight: 1, accuracy: High
        $x_1_5 = {80 7c 19 d7 c5 75 37 80 7c 19 d8 0f 75 30}  //weight: 1, accuracy: High
        $x_1_6 = {80 7c 19 d9 84 75 29 80 7c 19 de 48 75 22 80 7c 19 df 8d 75 1b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win64_Vedratve_A_2147725627_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Vedratve.A!dha"
        threat_id = "2147725627"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Vedratve"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {00 52 75 6e 42 61 63 6b 44 6f 6f 72 00}  //weight: 4, accuracy: High
        $x_4_2 = {00 31 34 34 2e 32 31 34 2e 32 35 2e 31 36 39 00}  //weight: 4, accuracy: High
        $x_2_3 = "bkservicedllIS" ascii //weight: 2
        $x_2_4 = "m32\\systemmailupline.dll" ascii //weight: 2
        $x_2_5 = "[DecryptIEHttpAuthPasswords]" ascii //weight: 2
        $x_2_6 = {54 4d 42 4d 53 52 56 2e 65 78 65 00 00 00 00 00 46 52 57 4b 5f 45 56 45 4e 54 5f 53 46 43 54 4c 43 4f 4d 5f 45 58 49 54 00}  //weight: 2, accuracy: High
        $x_2_7 = {53 74 61 72 74 20 74 68 65 20 62 61 63 6b 64 6f 6f 72 20 2e 2e 2e 2e 20 00}  //weight: 2, accuracy: High
        $x_2_8 = "inject proc send ie proxy " ascii //weight: 2
        $x_2_9 = "proxy user and password recv" ascii //weight: 2
        $x_1_10 = {5b 6e 64 31 32 33 5d 0d 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((2 of ($x_4_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}


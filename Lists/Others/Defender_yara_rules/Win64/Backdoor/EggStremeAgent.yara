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
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5b 2a 5d 20 25 2d 31 36 73 25 64 20 20 6f 70 65 6e 0a 00}  //weight: 10, accuracy: High
        $x_10_2 = {63 6f 6e 6e 65 63 74 49 64 20 3a 20 25 73 20 72 65 61 64 79 20 73 65 6e 64 20 73 69 7a 65 3a 25 64 0a 00}  //weight: 10, accuracy: High
        $x_10_3 = {57 69 6e 25 64 2e 25 64 20 25 64 00}  //weight: 10, accuracy: High
        $x_10_4 = {25 73 5c 23 23 23 25 73 23 23 23 25 73 00}  //weight: 10, accuracy: High
        $x_10_5 = {25 64 23 23 23 25 64 23 23 23 25 73 23 23 23 25 73 23 23 23 25 73 00}  //weight: 10, accuracy: High
        $x_1_6 = {23 23 23 33 30 23 23 23 [0-22] 23 23 23 34 34 33}  //weight: 1, accuracy: Low
        $x_1_7 = ".com###443" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}


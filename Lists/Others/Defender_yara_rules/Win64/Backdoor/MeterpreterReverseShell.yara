rule Backdoor_Win64_MeterpreterReverseShell_A_2147780008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/MeterpreterReverseShell.A"
        threat_id = "2147780008"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "MeterpreterReverseShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed}  //weight: 1, accuracy: High
        $x_1_2 = {3a 56 79 a7 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = {4c 77 26 07 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {57 89 9f c6 ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {12 96 89 e2 ff d5}  //weight: 1, accuracy: High
        $x_1_6 = {58 a4 53 e5 ff d5}  //weight: 1, accuracy: High
        $x_1_7 = {2d 06 18 7b ff d5}  //weight: 1, accuracy: High
        $x_1_8 = {75 46 9e 86 ff d5}  //weight: 1, accuracy: High
        $x_1_9 = {eb 55 2e 3b ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


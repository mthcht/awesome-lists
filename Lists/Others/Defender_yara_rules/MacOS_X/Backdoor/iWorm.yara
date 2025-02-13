rule Backdoor_MacOS_X_iWorm_A_2147689384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/iWorm.A"
        threat_id = "2147689384"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "iWorm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/tmp/.JavaW" ascii //weight: 1
        $x_1_2 = {47 45 54 20 25 73 20 48 54 54 50 2f 31 2e 30 [0-16] 48 6f 73 74 3a 20 25 73 [0-16] 41 63 63 65 70 74 3a 20 74 65 78 74 2f 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {25 32 64 25 32 64 25 32 64 25 32 64 25 32 64 25 32 64 5a 00 25 34 64 25 32 64 25 32 64 25 32 64 25 32 64 25 32 64 5a 00 4f 53 58 00 30 2e 32 32}  //weight: 1, accuracy: High
        $x_1_4 = {65 63 6b 65 79 2e 51 [0-32] 75 69 64 00 25 32 78 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_5 = {28 66 6f 72 20 67 65 6e 65 72 61 74 6f 72 29 00 28 66 6f 72 20 73 74 61 74 65 29 00 28 66 6f 72 20 63 6f 6e 74 72 6f 6c 29 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


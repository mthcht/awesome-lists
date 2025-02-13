rule Backdoor_Win64_BadHatch_B_2147812427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/BadHatch.B"
        threat_id = "2147812427"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "BadHatch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 61 69 6c 65 64 20 74 6f 20 65 78 65 63 75 74 65 20 43 56 45 20 64 6c 6c 20 66 72 6f 6d 20 6d 65 6d 6f 72 79 2c 20 65 72 ?? 6f 72 20 25 75}  //weight: 1, accuracy: Low
        $x_1_2 = {46 61 69 6c 65 64 20 74 6f 20 75 70 6c 6f 61 64 20 73 63 72 65 65 6e 73 68 6f 74 2c 20 65 72 72 6f ?? 20 25 75}  //weight: 1, accuracy: Low
        $x_1_3 = {46 61 69 6c 65 64 20 74 6f 20 6c 6f 61 64 20 50 53 20 6d 6f 64 75 6c 65 2c 20 65 72 72 6f ?? 20 25 75}  //weight: 1, accuracy: Low
        $x_1_4 = {50 6c 65 61 73 65 20 75 70 6c 6f 61 64 20 (32|33|34|36) (32|33|34|36) 2d 62 69 74 20 44 4c ?? 20 66 69 6c 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


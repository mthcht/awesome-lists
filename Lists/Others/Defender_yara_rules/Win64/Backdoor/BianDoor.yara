rule Backdoor_Win64_BianDoor_B_2147851921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/BianDoor.B"
        threat_id = "2147851921"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "BianDoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 6f 00 2f 68 6f 6d 65 2f 61 64 6d 69 6e 2f 70 72 6a 63 74 2f 67 6f 6c 61 6e 67 2f 73 6f 63 6b 73}  //weight: 1, accuracy: High
        $x_1_2 = {6d 61 69 6e 2e 63 6f 6e 6e 65 63 74 46 6f 72 53 6f 63 6b 73 2e 66 75 6e 63 31 00 6d 61 69 6e 2e 6d 61 69 6e}  //weight: 1, accuracy: High
        $x_1_3 = {2f 73 6f 63 6b 73 35 2e 67 6f 00 6f 75 74 2f [0-9] 2e [0-9] 2e [0-9] 2e [0-9] 2f [0-15] 2d [0-15] 2f 63 6c 69 65 6e 74 2f 6d 61 69 6e 2e 67 6f}  //weight: 1, accuracy: Low
        $x_1_4 = {2f 73 6f 63 6b 73 2f 6f 75 74 2f [0-9] 2e [0-9] 2e [0-9] 2e [0-9] 2f [0-15] 2d [0-15] 2f 63 6c 69 65 6e 74 2f 6d 61 69 6e 2e 67 6f}  //weight: 1, accuracy: Low
        $x_1_5 = {2f 73 6f 63 6b 73 35 2e 67 6f 00 6f 75 74 2f [0-50] 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 2f [0-15] 2d [0-15] 2f 63 6c 69 65 6e 74 2f 6d 61 69 6e 2e 67 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win64_BianDoor_D_2147903395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/BianDoor.D"
        threat_id = "2147903395"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "BianDoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 36 34 2e 64 6c 6c 00 45 6e 74 72 79 00 5f 63 67 6f 5f 64 75 6d 6d 79 5f 65 78 ?? 6f 72 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_BianDoor_H_2147922181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/BianDoor.H"
        threat_id = "2147922181"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "BianDoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 36 34 2e 64 6c 6c 00 45 6e 74 72 79 00 5f 63 67 6f 5f 64 75 ?? 6d 79 5f 65 78 ?? 6f 72 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


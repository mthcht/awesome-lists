rule Backdoor_Win32_Wisvereq_G_2147681993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wisvereq.G"
        threat_id = "2147681993"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wisvereq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 00}  //weight: 1, accuracy: High
        $x_1_2 = {75 70 66 69 6c 65 00 00 63 6d 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {61 62 00 00 25 [0-2] 64 [0-4] 6c 6f 61 64 66 69 6c 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Wisvereq_H_2147681995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wisvereq.H"
        threat_id = "2147681995"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wisvereq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 6d 64 2e 65 78 65 [0-5] 75 70 66 69 6c 65 [0-5] 6c 6f 61 64 66 69 6c 65}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 77 64 65 66 65 6e 67 [0-5] 6d 73 73 61 76 70 2e 65 78 65 [0-5] 4d 53 50 54 46 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Wisvereq_J_2147726031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wisvereq.J!dha"
        threat_id = "2147726031"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wisvereq"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 00}  //weight: 5, accuracy: High
        $x_5_2 = {4e 6f 49 50 0d 0a 00 00 4e 6f 4e 61 6d 65 0d 0a 00}  //weight: 5, accuracy: High
        $x_1_3 = {49 6d 61 67 69 6e 56 69 65 77 00}  //weight: 1, accuracy: High
        $x_1_4 = {64 32 68 73 63 48 4e 32 59 79 35 6b 62 47 77 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {65 62 76 69 33 30 37 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_6 = "Win2000" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Backdoor_MacOS_GetShell_A_2147658605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/GetShell.A"
        threat_id = "2147658605"
        type = "Backdoor"
        platform = "MacOS: "
        family = "GetShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 61 00 00 02 6a 02 5f 6a 01 5e 48 31 d2 0f 05 49 89 c4 48 89 c7 b8 62 00 00 02 48 31 f6 56 48 be ?? ?? ?? ?? ?? ?? ?? ?? 56 48 89 e6 6a 10 5a 0f 05 4c 89 e7 b8 5a 00 00 02 48 31 f6 0f 05 b8 5a 00 00 02 48 ff c6 0f 05 48 31 c0 b8 3b 00 00 02 e8 08 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_GetShell_A_2147658605_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/GetShell.A"
        threat_id = "2147658605"
        type = "Backdoor"
        platform = "MacOS: "
        family = "GetShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 00 00 61 44 00 00 02 7c 00 02 78 7c 7e 1b 78 48 00 00 0d 00 02 1f 90 ba 57 45 f9}  //weight: 1, accuracy: High
        $x_1_2 = {7c 00 02 78 38 00 00 03 7f c3 f3 78 38 81 e0 00 38 a0 20 00}  //weight: 1, accuracy: High
        $x_1_3 = {38 00 00 61 44 00 00 02 7c 00 02 78 7c 7e 1b 78 48 00 00 0d 00 02}  //weight: 1, accuracy: High
        $x_1_4 = {2f 62 69 6e 2f 63 73 68 00 41 41 41 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}  //weight: 1, accuracy: High
        $x_1_5 = {50 6a 01 6a 02 6a 10 b0 61 cd 80 57 50 50 6a}  //weight: 1, accuracy: High
        $x_1_6 = {6a 5a 58 cd 80 ff ?? ?? 79 [0-2] 68 2f 2f 73 68 68 2f 62 69 6e}  //weight: 1, accuracy: Low
        $x_1_7 = {50 40 50 40 50 52 b0 61 cd 80 0f [0-5] 89 c6 52 52 52 68 00 02 11 5c}  //weight: 1, accuracy: Low
        $x_1_8 = {66 b8 02 10 50 31 c0 b0 07 50 56 52 52 b0 c5 cd 80 72 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_MacOS_GetShell_B_2147750812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/GetShell.B!MTB"
        threat_id = "2147750812"
        type = "Backdoor"
        platform = "MacOS: "
        family = "GetShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {15 0f 01 00 00 00 00 1d b8 00 00 00 00 5f 5f 73 74 61 72 74 00 5f 63 6f 6d 6d 65 6e 74 00 5f 73 68 65 6c 6c 63 6f 64}  //weight: 5, accuracy: High
        $x_5_2 = {5f 5f 73 74 61 72 74 00 5f 63 6f 6d 6d 65 6e 74 00 5f 73 68 65 6c 6c 63 6f 64 65 00 5f 2e 73 74 72 00 00 00}  //weight: 5, accuracy: High
        $x_1_3 = "_shellcode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}


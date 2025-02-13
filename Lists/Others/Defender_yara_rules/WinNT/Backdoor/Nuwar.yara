rule Backdoor_WinNT_Nuwar_B_2147595771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Nuwar.B!sys"
        threat_id = "2147595771"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Nuwar"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 3d 93 08 75 07 8b 45 0c 8b 00 eb 1a 66 3d 28 0a 75 08 8b 45 0c 8b 40 04 eb 0c 66 3d ce 0e 75 18}  //weight: 1, accuracy: High
        $x_1_2 = {50 8b 45 fc fa 0f 22 c0 fb 58 8b c1}  //weight: 1, accuracy: High
        $x_1_3 = {8b ec 51 50 0f 20 c0 89 45 fc 25 ff ff fe ff fa 0f 22 c0 fb 58 8b 45 fc}  //weight: 1, accuracy: High
        $x_1_4 = {8b 45 0c 89 18 8b 7e 04 4f 78 31 8b c7 c1 e0 06 8d b4}  //weight: 1, accuracy: High
        $x_1_5 = {01 00 6a 40 8d 9b ?? ?? 01 00 8b 43 50 68 00 30 00 00 89 45 f4 8d 45 f4 50 6a 00 8d 45 fc 50 ff 75 08 ff 15}  //weight: 1, accuracy: Low
        $x_1_6 = {13 01 00 30 90 ?? ?? 01 00 40 3b c1 72 ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_WinNT_Nuwar_A_2147595783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Nuwar.A!sys"
        threat_id = "2147595783"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Nuwar"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 8b 00 66 3d 93 08 74 0c 66 3d 28 0a 74 06 66 3d ce 0e}  //weight: 2, accuracy: High
        $x_2_2 = {83 e8 10 75 02 33 f6 83 61 1c 00 32 d2 89 71 18}  //weight: 2, accuracy: High
        $x_2_3 = {00 56 56 68 ff 03 1f 00 ff 75 fc ff 15}  //weight: 2, accuracy: High
        $x_2_4 = {83 4d fc ff 56 c7 45 f8 80 0f 05 fd 33 f6 39 35}  //weight: 2, accuracy: High
        $x_2_5 = {6a 01 ff 75 0c c6 40 4a 01 56}  //weight: 2, accuracy: High
        $x_2_6 = {0f b7 c0 0f b7 c9 c1 e0 10 03 c1 3b c7 0f 97 c1 84 c9 74 05}  //weight: 2, accuracy: High
        $x_2_7 = {c7 45 fc 00 80 00 00 be 04 00 00 c0 68 44 64 6b 20 ff 75 fc}  //weight: 2, accuracy: High
        $x_2_8 = {83 7d 10 00 74 10 8b 4d 08 8a 45 0c ff 45 08 ff 4d 10 88 01 75 f0}  //weight: 2, accuracy: High
        $x_2_9 = {8d 45 ec 50 8d 45 d4 50 68 ff 0f 1f 00}  //weight: 2, accuracy: High
        $x_6_10 = {0f b7 43 14 8d 54 18 18 0f b7 43 06 83 65 08 00 8d 0c 80 c1 e1 03 b8}  //weight: 6, accuracy: High
        $x_1_11 = "KeServiceDescriptorTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_2_*) and 1 of ($x_1_*))) or
            ((9 of ($x_2_*))) or
            ((1 of ($x_6_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 6 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_WinNT_Nuwar_C_2147595864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Nuwar.C!sys"
        threat_id = "2147595864"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Nuwar"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 20 c0 50 25 ff ff fe ff 0f 22 c0}  //weight: 1, accuracy: High
        $x_1_2 = {74 00 63 00 68 00 64 00 6f 00 67 00 2e 00 73 00 79 00 73 00 00 00 00 00 7a 00 63 00 6c 00 69 00}  //weight: 1, accuracy: High
        $x_1_3 = {0f b7 00 56 33 f6 3d 93 08 00 00 89 75 fc 0f 84}  //weight: 1, accuracy: High
        $x_1_4 = {57 69 6e 45 78 65 63 00 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 00 00 73 70 6f 6f 6c 64 72 00}  //weight: 1, accuracy: High
        $x_1_5 = {65 78 70 6c 6f 72 65 72 00 00 00 00 7a 6c 63 6c}  //weight: 1, accuracy: High
        $x_10_6 = "PsSetLoadImageNotifyRoutine" ascii //weight: 10
        $x_10_7 = "ZwTerminateProcess" ascii //weight: 10
        $x_10_8 = "PsCreateSystemThread" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_WinNT_Nuwar_E_2147601230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Nuwar.E"
        threat_id = "2147601230"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Nuwar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 65 fc 00 33 c0 85 c9 76 11 8a 15 ?? ?? 01 00 30 90 ?? ?? 01 00 40 3b c1 72 ef 53 8b 1d ?? ?? 01 00 6a 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Backdoor_Win32_Deselia_A_2147696277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Deselia.A!dha"
        threat_id = "2147696277"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Deselia"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 30 30 30 45 4c 49 53 45 [0-8] 2e 54 4d 50}  //weight: 1, accuracy: Low
        $x_1_2 = "EliseDLL.dll" ascii //weight: 1
        $x_1_3 = {45 53 45 6e 74 72 79 00 45 53 48 61 6e 64 6c 65 00}  //weight: 1, accuracy: High
        $x_2_4 = {25 7f 00 00 80 79 05 48 83 c8 80 40 30 06 47}  //weight: 2, accuracy: High
        $x_1_5 = {53 bb 00 00 00 00 b8 01 00 00 00 0f 3f 07 0b 85 db 0f 94 45 e7 5b}  //weight: 1, accuracy: High
        $x_1_6 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Deselia_B_2147696278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Deselia.B!dha"
        threat_id = "2147696278"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Deselia"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 6f 61 64 65 72 44 4c 4c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 53 65 74 74 69 6e 67 00 55 70 64 61 74 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 01 8d 49 fe 30 41 03 0f b6 41 01 30 41 02 4a 75 ed}  //weight: 1, accuracy: High
        $x_1_4 = {8a 4c 30 ff 30 0c 30 48 85 c0 7f f4 80 36 ?? 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


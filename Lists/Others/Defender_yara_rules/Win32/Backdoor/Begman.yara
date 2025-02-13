rule Backdoor_Win32_Begman_A_2147643747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Begman.A"
        threat_id = "2147643747"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Begman"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {74 0c 8d 55 fc 8b c6 e8 ?? ?? ff ff eb 0d 46 83 c3 04 83 fe 03 0f 85 5f ff ff ff 69 05 ?? ?? ?? ?? 60 ea 00 00 50 a1 ?? ?? ?? ?? 8b 00 ff 50 18 e9 2e ff ff ff}  //weight: 5, accuracy: Low
        $x_1_2 = {0b 00 00 00 63 6c 62 63 61 74 71 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {09 00 00 00 69 6e 74 65 72 76 61 6c 22 00}  //weight: 1, accuracy: High
        $x_1_4 = {09 00 00 00 73 6f 63 6b 73 69 6e 74 22 00}  //weight: 1, accuracy: High
        $x_1_5 = {06 00 00 00 73 6f 63 6b 73 22 00}  //weight: 1, accuracy: High
        $x_1_6 = {08 00 00 00 73 65 6c 66 64 65 6c 22 00}  //weight: 1, accuracy: High
        $x_1_7 = {05 00 00 00 65 78 65 63 22 00}  //weight: 1, accuracy: High
        $x_1_8 = {0a 00 00 00 2c 4d 61 69 6e 42 65 67 69 6e 00}  //weight: 1, accuracy: High
        $x_2_9 = {0c 00 00 00 77 75 73 61 20 2f 71 75 69 65 74 20 00}  //weight: 2, accuracy: High
        $x_2_10 = {1f 00 00 00 5b 61 75 74 6f 72 75 6e 5d 0d 0a 55 73 65 41 75 74 6f 50 6c 61 79 3d 31 0d 0a 6f 70 65 6e 3d 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Begman_B_2147645654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Begman.B"
        threat_id = "2147645654"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Begman"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "wusa /quiet " ascii //weight: 3
        $x_2_2 = ",MainBegin" ascii //weight: 2
        $x_2_3 = "shell\\Explore\\command=" ascii //weight: 2
        $x_2_4 = "expand -r " ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Begman_C_2147651232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Begman.C"
        threat_id = "2147651232"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Begman"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {10 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20}  //weight: 1, accuracy: High
        $x_1_2 = {56 42 4f 58 [0-15] 51 45 4d 55 [0-10] 55 8b ec 6a 00 6a 00 53 56}  //weight: 1, accuracy: Low
        $x_1_3 = "expand -r " ascii //weight: 1
        $x_1_4 = "wusa.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Begman_D_2147654667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Begman.D"
        threat_id = "2147654667"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Begman"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f2 8a 10 8b d9 c1 eb 08 32 da 88 18 81 e2 ff 00 00 00 03 ca 0f af 4d 08 40 4e 85 f6 75 e3 5e}  //weight: 1, accuracy: High
        $x_1_2 = {50 68 34 4d 40 00 68 a4 43 40 00 e8 5f db ff ff a1 a0 53 40 00 50 a1 9c 53 40 00 50 68 ac 42 40 00 68 c0 3b 40 00 e8 44 db ff ff e8 83 08 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {56 42 4f 58 [0-15] 51 45 4d 55 [0-10] 55 8b ec 6a 00 6a 00 53 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


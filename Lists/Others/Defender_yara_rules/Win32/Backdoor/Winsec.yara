rule Backdoor_Win32_Winsec_A_2147706524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Winsec.A!dha"
        threat_id = "2147706524"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Winsec"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 77 ff 4f c1 e2 08 0b d6 4b f6 c3 03 75 05 83 e8 04 89 10}  //weight: 2, accuracy: High
        $x_2_2 = {80 3f 00 74 10 8a 07 3c 2e 74 07 3c 20 74 03 88 03 43}  //weight: 2, accuracy: High
        $x_1_3 = {2e 47 65 2e 74 45 2e 78 69 20 74 43 2e 6f 64 20 65 50 2e 20 72 6f 63 20 65 2e 73 73 00}  //weight: 1, accuracy: High
        $x_2_4 = {9f 98 c6 b8 fc 20 24 cf 91 a7 73 01 d5 66 d3 31}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Winsec_B_2147706525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Winsec.B!dha"
        threat_id = "2147706525"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Winsec"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {3c 2e 74 07 3c 20 74 03 88}  //weight: 3, accuracy: High
        $x_1_2 = {2e 47 65 2e 74 45 2e 78 69 20 74 43 2e 6f 64 20 65 50 2e 20 72 6f 63 20 65 2e 73 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {52 2e 20 65 2e 67 51 75 2e 2e 65 20 72 79 56 2e 61 6c 2e 75 65 45 20 78 41 00}  //weight: 1, accuracy: High
        $x_1_4 = {52 2e 2e 20 65 67 4f 70 2e 20 2e 65 6e 4b 2e 65 79 41 20 00}  //weight: 1, accuracy: High
        $x_1_5 = {52 65 2e 2e 67 44 65 6c 2e 65 74 65 56 61 2e 20 6c 75 65 57 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Winsec_C_2147707752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Winsec.C!dha"
        threat_id = "2147707752"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Winsec"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 03 3c 61 0f be c0 7d 05 83 e8 30 eb 03 83 e8 57 66 01 06 8a 43 01 43 84 c0 75}  //weight: 2, accuracy: High
        $x_2_2 = {8b 4c 24 08 8b 44 24 04 85 c9 7e 0e 8a 10 80 ?? ?? 80 ?? ?? 88 10 40 49 75 f2}  //weight: 2, accuracy: Low
        $x_2_3 = {83 f8 1a 7d 09 83 c0 61 c3 83 f8 1a 7c 09 83 f8 34 7d 09 83 c0 27 c3 83 f8 34 7c 09 83 f8 3e 7d 07 83 c0 fc}  //weight: 2, accuracy: High
        $x_1_4 = "RESPONSE 200 OK!!!" ascii //weight: 1
        $x_1_5 = "POST HTTP REQUEST?" ascii //weight: 1
        $x_2_6 = "%s /c \"%s\" >%s 2>&1" ascii //weight: 2
        $x_2_7 = "There aren`t open ports." ascii //weight: 2
        $x_2_8 = "cm%sx%s\"%s %s %s\" 2>%s" ascii //weight: 2
        $x_2_9 = "%s\\%c%c%c%c%c%c%c%c%s" ascii //weight: 2
        $x_1_10 = "2YqH7DEPYKZ67wPgqv7Zc" ascii //weight: 1
        $x_1_11 = "rwYgqYl77DeYDbumzZgbie7q" ascii //weight: 1
        $x_1_12 = "zqgwqzYwQvCYrqwDFvibgqCeYwc" ascii //weight: 1
        $x_1_13 = "2YqcvZO70lewYgO3w7CYiiKO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}


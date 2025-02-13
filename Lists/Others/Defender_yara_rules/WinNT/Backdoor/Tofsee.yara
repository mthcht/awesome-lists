rule Backdoor_WinNT_Tofsee_A_2147595466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Tofsee.A!sys"
        threat_id = "2147595466"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Tofsee"
        severity = "Low"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0f 20 c0 50 25 ff ff fe ff 0f 22 c0 8b 45 08 89 41 01 8b 45 0c 2b c1 83 e8 0a c6 01 b9 c6 41 05 e9}  //weight: 3, accuracy: High
        $x_3_2 = {89 41 06 58 0f 22 c0 66 9d 8b c1 5d c2 08 00 53 56 57 bf 2e 6b 64 44 57 68 80 00 00 00 33}  //weight: 3, accuracy: High
        $x_6_3 = {74 10 8a 10 88 14 01 40 3b 45 08 75 f5 eb 03 8b 5d f8 8b 4d fc 8b 46 04 89 4e 04 8b f1 eb 07 4f}  //weight: 6, accuracy: High
        $x_1_4 = "NtQuerySystemInformation" ascii //weight: 1
        $x_1_5 = "MoveFileExA" ascii //weight: 1
        $x_1_6 = "NtWriteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_WinNT_Tofsee_A_2147601144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Tofsee.A"
        threat_id = "2147601144"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Tofsee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2b fe 8a c1 ?? ?? b3 ?? f6 eb 8d 14 31 32 04 17 41 81 f9 ?? ?? 00 00 88 02 75 e7}  //weight: 3, accuracy: Low
        $x_2_2 = {47 47 66 3b c3 75 f5 8d ?? ?? f7 ff ff be ?? ?? ?? ?? 50 f3 a5}  //weight: 2, accuracy: Low
        $x_2_3 = {68 c0 a6 00 00 8d ?? ?? ?? ff ff 50 8d 45 ?? 50 53}  //weight: 2, accuracy: Low
        $x_1_4 = "/index.html" wide //weight: 1
        $x_1_5 = {48 6f 74 20 69 6e 74 65 72 6e 65 74 20 6f 66 66 65 72 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_WinNT_Tofsee_D_2147632400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Tofsee.D"
        threat_id = "2147632400"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Tofsee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 c9 39 4c 24 08 76 0f 8b 44 24 04 03 c1 f6 10 41 3b 4c 24 08 72 f1}  //weight: 2, accuracy: High
        $x_2_2 = {68 5f 4e 54 4c ff 74 24 08 ff 15}  //weight: 2, accuracy: High
        $x_2_3 = {8b 0f 8b 41 3c 8d 44 08 04 0f b7 50 02 0f b7 40 10 89 55 f8 6b d2 28}  //weight: 2, accuracy: High
        $x_1_4 = "\\rotcetorp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}


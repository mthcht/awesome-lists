rule Spammer_Win32_Cutwail_B_2147598318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Cutwail.gen!B"
        threat_id = "2147598318"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 6a 05 a3 ?? ?? ?? 13 a3 ?? ?? ?? 13 a3 ?? ?? ?? 13 58 6a 1c 6a 00 68 ?? ?? 15 13 c7 05}  //weight: 1, accuracy: Low
        $x_1_2 = {74 07 80 0d ?? ?? ?? 13 04 6a 05 58 6a 20 56 68 ?? ?? ?? 13 c7 05 ?? ?? ?? 13 ?? ?? 00 00 c7 05}  //weight: 1, accuracy: Low
        $x_1_3 = {74 07 80 0d ?? ?? ?? 13 04 8b 0d ?? ?? ?? 14 68 ?? ?? ?? ?? 56 68 ?? ?? ?? 13 c7 05 ?? ?? ?? 13 ?? ?? 00 00 e8 ?? ?? 00 00 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Spammer_Win32_Cutwail_A_2147598459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Cutwail.gen!A"
        threat_id = "2147598459"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 17 52 e8 ?? ?? 00 00 0f b6 05 ?? ?? ?? 00 0f b6 0d ?? ?? ?? 00 50 a1 ?? ?? ?? 00 51 0f b6 d4 52 0f b6 c0 50 68}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 17 51 e8 ?? ?? 00 00 0f b6 15 ?? ?? ?? 13 0f b6 05 ?? ?? ?? 13 52 50 a1 ?? ?? ?? 13 0f b6 cc 51 0f b6 d0 52 68}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 17 ff 70 0c e8 ?? ?? ff ff 0f b6 05 ?? ?? ?? ?? 50 0f b6 05 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? 0f b6 cc 51 0f b6 c0 50 68}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 17 ff 77 0c e8 ?? ?? ff ff 6a 12 e8 ?? ?? ff ff 89 45 fc 0f b6 05 ?? ?? ?? ?? 50 0f b6 05 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? 0f b6 cc 51 0f b6 c0 50 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Spammer_Win32_Cutwail_C_2147599379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Cutwail.gen!C"
        threat_id = "2147599379"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {30 16 46 49 75 f4 83 65 fc 00 8d 48 1c 8b 55 fc 8a 19 ff 45 fc 8d 3c 10 8a 17 88 11 49 83 7d fc 0e 88 1f 72 e8 f6 45 f8 01 74 0b 33 c9 f6 14 08}  //weight: 3, accuracy: High
        $x_1_2 = {81 3e 00 01 02 03 75 09 81 7e 04 04 05 06 07 74 03 46 eb ec}  //weight: 1, accuracy: High
        $x_1_3 = "bot_id=%d&mode" ascii //weight: 1
        $x_1_4 = "b%d,f%d" wide //weight: 1
        $x_1_5 = "\\\\.\\Runtime" ascii //weight: 1
        $x_1_6 = "Scriptor: Success interpretate script." ascii //weight: 1
        $x_1_7 = "Fail START RegAcc." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_Cutwail_D_2147626700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Cutwail.gen!D"
        threat_id = "2147626700"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Cutwail"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 0d 8a 14 30 30 54 01 04 40 3b 41 ?? 72 f3 5e}  //weight: 1, accuracy: Low
        $x_1_2 = {68 58 02 00 00 03 c6 50 ff 75 08 c7 45 ?? 78 56 34 12}  //weight: 1, accuracy: Low
        $x_1_3 = {66 39 46 06 89 45 fc 76 57 8d be 08 01 00 00 8b 0f 85 c9 74 37 80 7d 0f 00 74 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


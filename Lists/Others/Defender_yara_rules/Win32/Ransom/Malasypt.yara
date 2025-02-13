rule Ransom_Win32_Malasypt_A_2147711097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Malasypt.A"
        threat_id = "2147711097"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Malasypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "momsbestfriend@protonmail.com or torrenttracker@india.com" ascii //weight: 4
        $x_4_2 = "send me a message at BM-NBvzKEY8raDBKb9Gp1xZMRQpeU5svwg2" ascii //weight: 4
        $x_4_3 = "Your files are now encrypted. I have the key to decrypt them back." ascii //weight: 4
        $x_2_4 = {c7 00 6e 00 74 00 c7 40 04 64 00 6c 00 c7 40 08 6c 00 00 00}  //weight: 2, accuracy: High
        $x_4_5 = {6a 09 50 ff 35 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 00 ff d0 0b c0 74 31 ff 75 08 e8 ?? ?? ff ff 40 8b c8 d1 e1 8d 45 fc 6a 00 50 51 ff 75 08 ff 35 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 00 ff d0}  //weight: 4, accuracy: Low
        $x_2_6 = {d1 e0 c7 04 10 2a 00 2e 00 c6 44 10 04 2a ff 75 fc ff 75 f8}  //weight: 2, accuracy: High
        $x_2_7 = {75 1e 83 7f 2c 2e 74 18 81 7f 2c 2e 00 2e 00 74 0f}  //weight: 2, accuracy: High
        $x_2_8 = {74 6e 8b f8 ff 76 08 8f 47 08 ff 76 04 8f 47 04 ff 36 8f 07}  //weight: 2, accuracy: High
        $x_4_9 = {66 8b 04 8a 66 3d ?? ?? 74 0c 66 3d ?? ?? 74 06 66 3d ?? ?? 75 09 c7 45 f4 01 00 00 00 eb 06 41 3b 4d f8 75 db ff 75 fc}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Malasypt_A_2147711098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Malasypt.A!!Malasypt.gen!A"
        threat_id = "2147711098"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Malasypt"
        severity = "Critical"
        info = "Malasypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "momsbestfriend@protonmail.com or torrenttracker@india.com" ascii //weight: 4
        $x_4_2 = "send me a message at BM-NBvzKEY8raDBKb9Gp1xZMRQpeU5svwg2" ascii //weight: 4
        $x_4_3 = "Your files are now encrypted. I have the key to decrypt them back." ascii //weight: 4
        $x_2_4 = {c7 00 6e 00 74 00 c7 40 04 64 00 6c 00 c7 40 08 6c 00 00 00}  //weight: 2, accuracy: High
        $x_4_5 = {6a 09 50 ff 35 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 00 ff d0 0b c0 74 31 ff 75 08 e8 ?? ?? ff ff 40 8b c8 d1 e1 8d 45 fc 6a 00 50 51 ff 75 08 ff 35 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 00 ff d0}  //weight: 4, accuracy: Low
        $x_2_6 = {d1 e0 c7 04 10 2a 00 2e 00 c6 44 10 04 2a ff 75 fc ff 75 f8}  //weight: 2, accuracy: High
        $x_2_7 = {75 1e 83 7f 2c 2e 74 18 81 7f 2c 2e 00 2e 00 74 0f}  //weight: 2, accuracy: High
        $x_2_8 = {74 6e 8b f8 ff 76 08 8f 47 08 ff 76 04 8f 47 04 ff 36 8f 07}  //weight: 2, accuracy: High
        $x_4_9 = {66 8b 04 8a 66 3d ?? ?? 74 0c 66 3d ?? ?? 74 06 66 3d ?? ?? 75 09 c7 45 f4 01 00 00 00 eb 06 41 3b 4d f8 75 db ff 75 fc}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}


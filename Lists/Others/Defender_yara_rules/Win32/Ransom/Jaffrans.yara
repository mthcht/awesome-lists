rule Ransom_Win32_Jaffrans_A_2147721435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Jaffrans.A!rsm"
        threat_id = "2147721435"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaffrans"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 ee 18 3b cb 7d 08 8b 55 08 8a 14 11 eb 02 32 d2 c1 e0 08 0f be d2 0b c2 33 84 b5 ?? ?? ?? ?? 41 3b cf 7c}  //weight: 2, accuracy: Low
        $x_2_2 = {ff d3 ff d3 3d 16 00 09 80 0f 85 ?? ?? ?? ?? 68 08 00 00 f0 6a 18 57 57 8d 4d fc 51 ff d6}  //weight: 2, accuracy: Low
        $x_2_3 = {33 c0 8d 4b 41 52 66 89 45 ?? 88 4d ?? ff 15 ?? ?? ?? ?? 83 f8 05 74 ?? 8d 45 ?? 50 ff 15 ?? ?? ?? ?? 8d 4c 00 02 51 6a 08 ff 15}  //weight: 2, accuracy: Low
        $x_2_4 = {66 8b 08 83 c0 02 66 85 c9 75 ?? 2b c2 d1 f8 8b d3 74 ?? 8b fe 8d 4d ?? 2b f9 8d 9b 00 00 00 00 8a 8b ?? ?? ?? ?? 8d 34 57 32 4c 35}  //weight: 2, accuracy: Low
        $x_2_5 = "jaff decryptor system" ascii //weight: 2
        $x_1_6 = {2e 00 78 00 6c 00 73 00 78 00 00 00 2e 00 61 00 63 00 64 00 00 00 2e 00 70 00 64 00 66 00 00 00 2e 00 70 00 66 00 78 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = "decrypt your files, is located on a secret server" ascii //weight: 1
        $x_1_8 = "JAFF DECRYPTOR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Jaffrans_A_2147721438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Jaffrans.A!!Jaffrans.gen!A"
        threat_id = "2147721438"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaffrans"
        severity = "Critical"
        info = "Jaffrans: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 ee 18 3b cb 7d 08 8b 55 08 8a 14 11 eb 02 32 d2 c1 e0 08 0f be d2 0b c2 33 84 b5 ?? ?? ?? ?? 41 3b cf 7c}  //weight: 2, accuracy: Low
        $x_2_2 = {ff d3 ff d3 3d 16 00 09 80 0f 85 ?? ?? ?? ?? 68 08 00 00 f0 6a 18 57 57 8d 4d fc 51 ff d6}  //weight: 2, accuracy: Low
        $x_2_3 = {33 c0 8d 4b 41 52 66 89 45 ?? 88 4d ?? ff 15 ?? ?? ?? ?? 83 f8 05 74 ?? 8d 45 ?? 50 ff 15 ?? ?? ?? ?? 8d 4c 00 02 51 6a 08 ff 15}  //weight: 2, accuracy: Low
        $x_2_4 = {66 8b 08 83 c0 02 66 85 c9 75 ?? 2b c2 d1 f8 8b d3 74 ?? 8b fe 8d 4d ?? 2b f9 8d 9b 00 00 00 00 8a 8b ?? ?? ?? ?? 8d 34 57 32 4c 35}  //weight: 2, accuracy: Low
        $x_2_5 = "jaff decryptor system" ascii //weight: 2
        $x_1_6 = {2e 00 78 00 6c 00 73 00 78 00 00 00 2e 00 61 00 63 00 64 00 00 00 2e 00 70 00 64 00 66 00 00 00 2e 00 70 00 66 00 78 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = "decrypt your files, is located on a secret server" ascii //weight: 1
        $x_1_8 = "JAFF DECRYPTOR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Jaffrans_B_2147721599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Jaffrans.B"
        threat_id = "2147721599"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaffrans"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<title>jaff" ascii //weight: 1
        $x_1_2 = "Your decrypt ID:" ascii //weight: 1
        $x_1_3 = "After instalation, run the Tor Browser and enter address:" ascii //weight: 1
        $x_1_4 = "To decrypt flies you need to obtain the private" ascii //weight: 1
        $x_2_5 = {89 45 f8 3d 00 00 08 00 76 0a b8 00 00 08 00 89 45 f8 eb 07 c7 45 fc 01 00 00 00 57 50 6a 08}  //weight: 2, accuracy: High
        $x_2_6 = {8d 44 24 58 50 ff d6 85 c0 0f 84 ?? ?? 00 00 8d 4c 24 54 51 ff 15 ?? ?? ?? ?? f6 44 24 28 14}  //weight: 2, accuracy: Low
        $x_2_7 = {8b 45 f8 53 8d 55 e8 52 50 57 56 89 5d e8 ff 15 ?? ?? ?? ?? 8b 5d 0c 8d 4d f4 89 7d f4 51 8d 7d f8 e8}  //weight: 2, accuracy: Low
        $x_2_8 = {ff d7 6a 02 6a 00 6a 00 56 ff 15 ?? ?? ?? ?? 8b 55 ec 6a 00 8d 4d fc 51 52 53 56 ff d7}  //weight: 2, accuracy: Low
        $x_2_9 = {8d 43 41 51 66 89 55 f6 88 45 f0 ff 15 ?? ?? ?? ?? 83 f8 05 74 ?? 8d 55 f0 52 ff 15 ?? ?? ?? ?? 8d 44 00 02}  //weight: 2, accuracy: Low
        $x_2_10 = {ff d3 ff d3 3d 16 00 09 80 0f 85 ?? ?? ?? ?? 68 08 00 00 f0 6a 18 57 57 8d 4d fc 51 ff d6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Jaffrans_B_2147721601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Jaffrans.B!!Jaffrans.gen!A"
        threat_id = "2147721601"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaffrans"
        severity = "Critical"
        info = "Jaffrans: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<title>jaff" ascii //weight: 1
        $x_1_2 = "Your decrypt ID:" ascii //weight: 1
        $x_1_3 = "After instalation, run the Tor Browser and enter address:" ascii //weight: 1
        $x_1_4 = "To decrypt flies you need to obtain the private" ascii //weight: 1
        $x_2_5 = {89 45 f8 3d 00 00 08 00 76 0a b8 00 00 08 00 89 45 f8 eb 07 c7 45 fc 01 00 00 00 57 50 6a 08}  //weight: 2, accuracy: High
        $x_2_6 = {8d 44 24 58 50 ff d6 85 c0 0f 84 ?? ?? 00 00 8d 4c 24 54 51 ff 15 ?? ?? ?? ?? f6 44 24 28 14}  //weight: 2, accuracy: Low
        $x_2_7 = {8b 45 f8 53 8d 55 e8 52 50 57 56 89 5d e8 ff 15 ?? ?? ?? ?? 8b 5d 0c 8d 4d f4 89 7d f4 51 8d 7d f8 e8}  //weight: 2, accuracy: Low
        $x_2_8 = {ff d7 6a 02 6a 00 6a 00 56 ff 15 ?? ?? ?? ?? 8b 55 ec 6a 00 8d 4d fc 51 52 53 56 ff d7}  //weight: 2, accuracy: Low
        $x_2_9 = {8d 43 41 51 66 89 55 f6 88 45 f0 ff 15 ?? ?? ?? ?? 83 f8 05 74 ?? 8d 55 f0 52 ff 15 ?? ?? ?? ?? 8d 44 00 02}  //weight: 2, accuracy: Low
        $x_2_10 = {ff d3 ff d3 3d 16 00 09 80 0f 85 ?? ?? ?? ?? 68 08 00 00 f0 6a 18 57 57 8d 4d fc 51 ff d6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}


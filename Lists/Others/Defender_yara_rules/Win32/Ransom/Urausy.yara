rule Ransom_Win32_Urausy_A_2147659866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Urausy.A"
        threat_id = "2147659866"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Urausy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 87 04 24 8b 04 03 21 c0 74 10 8b 10 80 fa cc 74 09 66 81 fa eb fe 74 02 ff e0}  //weight: 1, accuracy: High
        $x_1_2 = {b9 06 00 00 00 f3 ab c7 85 ?? ?? ff ff 18 00 00 00 c7 85 ?? ?? ff ff 40 00 00 00 8d 8d ?? ?? ff ff 8d 95 ?? ?? ff ff 8d 45 f8 51 52 6a 3a 50 68 ?? ?? 00 00 e8 ?? ?? ?? ?? 09 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Urausy_C_2147670619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Urausy.C"
        threat_id = "2147670619"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Urausy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 3e 53 45 4c 46 0f 84 ?? ?? ?? ?? 81 3e 00 50 4b 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c9 ff 31 c0 f2 66 af c7 47 fa 6e 00 69 00 c7 47 f6 2e 00 69 00 56 ff 93 ?? ?? ?? ?? c7 47 fa 61 00 74 00 c7 47 f6 2e 00 64 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Urausy_E_2147680191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Urausy.E"
        threat_id = "2147680191"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Urausy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 3e 53 45 4c 46 0f 84 ?? ?? ?? ?? 81 3e 00 50 4b 00}  //weight: 1, accuracy: Low
        $x_1_2 = {89 f7 83 c9 ff 31 c0 f2 ae c7 47 fb 2e 69 6e 69 56 ff 93}  //weight: 1, accuracy: High
        $x_1_3 = {c7 01 00 10 00 00 6a 40 68 00 10 00 00 51 50 57 6a ff ff 93 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Urausy_E_2147680191_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Urausy.E"
        threat_id = "2147680191"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Urausy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 b9 00 10 00 00 ff 74 0e ff 58 d0 c0 34 11 8b d8}  //weight: 1, accuracy: High
        $x_1_2 = {b9 0d 00 00 00 83 c0 01 6a 00 68 ?? ?? ?? ?? 68 [0-1] 63 6f 6d [0-1] 68 ?? ?? ?? ?? 8b f9 03 fc 4f 8b 3f 81 e7 ff 00 00 00 8b df 8b d6 03 d1 88 5c 02 ff e2 e7 83 c4 10 61}  //weight: 1, accuracy: Low
        $x_1_3 = {68 04 01 00 00 56 8b ?? e4 01 00 00 ff d0 e8 ?? 00 00 00 ff ?? 70 01 00 00 ff 14 24 ff ?? 80 01 00 00 6a 00 56 ff ?? 24 08 50 ff ?? 70 01 00 00 ff 14 24 58 58 [0-15] 68 00 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Urausy_E_2147680191_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Urausy.E"
        threat_id = "2147680191"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Urausy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 63 3a 5c 74 65 6d 70 5c 66 69 6c 6f 74 66 2e 74 78 74 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {30 00 66 00 77 00 77 00 65 00 67 00 64 00 33 00 5f 00 32 00 66 00 65 00 6c 00 66 00 6b 00 6b 00 6b 00 6b 00 6b 00 6b 00 6b 00 6b 00 6b 00 6b 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_2_3 = {83 c4 04 89 45 e8 83 7d e8 63 72 0a 8b 4d 08}  //weight: 2, accuracy: High
        $x_2_4 = {c7 45 e8 00 00 40 00 c7 45 fc ?? ?? ?? ?? c7 45 dc 00 00 00 00 c7 45 f0 00 00 00 00 c7 45 ec 00 00 00 00 c7 45 c4 ?? ?? 00 00 8f 45 c0 c7 45 bc 00 00 00 00 eb 09 8b 55 bc 83 c2 01 89 55 bc 83 7d bc 0a}  //weight: 2, accuracy: Low
        $x_2_5 = {89 45 cc ff 75 cc ff 15 ?? 30 40 00 c7 45 f4 ?? 18 00 00 83 7d f4 00 74 17 c7 45 d4 3a 00 00 00 c7 45 e0 10 00 00 00 8b 0d ?? 30 40 00 89 4d d8}  //weight: 2, accuracy: Low
        $x_2_6 = {40 00 c7 45 ?? ?? 18 00 00 c7 45 ?? 3a 00 00 00 c7 45 ?? 10 00 00 00 8b ?? ?? ?? 40 00 89 ?? d4 c7 45 ?? 00 00 40 00 c7 45 fc ?? ?? ?? ?? c7 45 c0 ?? ?? 00 00 8f 45 bc c7 45 ?? 00 00 00 00 eb 09 8b 55 b8 83 c2 01 89 55 b8 83 7d b8 0a 73 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Urausy_I_2147688124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Urausy.I"
        threat_id = "2147688124"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Urausy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d c4 89 4a 01 c6 42 05 83 c6 42 06 2c c6 42 07 24 c6 42 08 05}  //weight: 1, accuracy: High
        $x_1_2 = {89 f7 83 c9 ff 31 c0 f2 ae c7 47 fb 2e (69|74) 56 ff 93}  //weight: 1, accuracy: Low
        $x_1_3 = {5b b0 2e aa b8 68 74 6d 6c ab 31 c0 aa}  //weight: 1, accuracy: High
        $x_1_4 = "%x%x.xml" wide //weight: 1
        $x_1_5 = {26 6c 74 3b 00 26 67 74 3b 00 26 61 6d 70 3b 00 47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Urausy_I_2147688124_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Urausy.I"
        threat_id = "2147688124"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Urausy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d c4 89 4a 01 c6 42 05 83 c6 42 06 2c c6 42 07 24 c6 42 08 05}  //weight: 1, accuracy: High
        $x_1_2 = {89 f7 83 c9 ff 31 c0 f2 ae c7 47 fb 2e 69 6e 66 56 ff 93}  //weight: 1, accuracy: High
        $x_1_3 = {5b b0 2e aa b8 68 74 6d 6c ab 31 c0 aa}  //weight: 1, accuracy: High
        $x_1_4 = "%x%x.xml" wide //weight: 1
        $x_1_5 = {26 6c 74 3b 00 26 67 74 3b 00 26 61 6d 70 3b 00 47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Urausy_I_2147691870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Urausy.I!!Urausy.gen!A"
        threat_id = "2147691870"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Urausy"
        severity = "Critical"
        info = "Urausy: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 76 3c 6a 40 68 00 10 00 00 ff 76 50 ff 76 34 ff 93 ?? ?? 00 00 09 c0 75 26 39 86 a0 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {89 4a 01 c6 42 05 83 c6 42 06 2c c6 42 07 24 c6 42 08 05}  //weight: 1, accuracy: High
        $x_1_3 = {89 4a 02 c6 42 0a 48 c6 42 0b 83 c6 42 0c 2c c6 42 0d 24 c6 42 0e 05}  //weight: 1, accuracy: High
        $x_1_4 = {5b b0 2e aa b8 68 74 6d 6c ab 31 c0 aa}  //weight: 1, accuracy: High
        $x_1_5 = {f2 ae c7 47 fb 2e ?? ?? ?? 56 ff 93 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {01 da ff 42 04 0f b7 47 05 8c 8e ?? ?? 00 00 66 89 86 ?? ?? 00 00 8b 8b ?? ?? 00 00 89 8e ?? ?? 00 00 8d 93 ?? ?? 00 00 89 55 f8 89 45 fc}  //weight: 1, accuracy: Low
        $x_1_7 = {8d 85 00 ff ff ff 83 c7 10 83 e9 10 89 8d f4 fe ff ff 50 6a 10 ff b5 f0 fe ff ff 51 57 e8 ?? ?? ?? ?? 66 81 3f 4d 5a}  //weight: 1, accuracy: Low
        $x_1_8 = {89 45 e0 80 bd ?? ?? ff ff 30 74 12 80 bd ?? ?? ff ff 31 0f 84 ?? ?? 00 00 e9 ?? ?? ff ff 31 c0 88 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_9 = {24 df 3c 58 75 ?? ac 84 c0 0f 84 ?? ?? 00 00 24 df 3c 4d 0f 85 ?? ?? 00 00 ac 84 c0 0f 84 ?? ?? 00 00 24 df 3c 4c}  //weight: 1, accuracy: Low
        $x_1_10 = "%x%x.xml" wide //weight: 1
        $x_1_11 = {26 6c 74 3b 00 26 67 74 3b 00 26 61 6d 70 3b 00 47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 41}  //weight: 1, accuracy: High
        $x_1_12 = {50 ff 75 fc ff 93 ?? ?? 00 00 85 c0 74 16 31 c0 8d 8b ?? ?? 00 00 89 01 8b 55 fc 89 51 04 89 41 08 89 41 0c 5f 5e 5b}  //weight: 1, accuracy: Low
        $x_1_13 = {e8 00 00 00 00 5b 81 eb ?? ?? 00 00 8b 93 ?? ?? 00 00 03 52 60 89 55 fc bf 3c 00 00 00 6a 01 e8 ?? ?? ?? ?? 68 e8 03 00 00 ff 93 ?? ?? 00 00 8b 83 ?? ?? 00 00 09 c0 75 03 4f 79 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


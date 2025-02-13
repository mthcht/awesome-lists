rule Ransom_Win32_Anunau_A_2147723865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Anunau.A"
        threat_id = "2147723865"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Anunau"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 00 65 00 76 00 69 00 63 00 65 00 49 00 44 00 00 00 00 00 01 00 00 00 44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 00 00 44 69 73 61 62 6c 65 52 6f 75 74 69 6e 65 6c 79 54 61 6b 69 6e 67 41 63 74 69 6f 6e 00 00 00 00 53 4f 46 54}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Anunau_A_2147723865_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Anunau.A"
        threat_id = "2147723865"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Anunau"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 25 30 38 58 25 30 38 58 25 63 00}  //weight: 1, accuracy: High
        $x_1_2 = "Invmod of %d %% %d" ascii //weight: 1
        $x_1_3 = "plumber@cock.li" ascii //weight: 1
        $x_1_4 = "decryption,so you will pay me and them anyways.Please" ascii //weight: 1
        $x_1_5 = "call uninstall /nointeractive" ascii //weight: 1
        $x_1_6 = "DisableRoutinelyTakingAction" ascii //weight: 1
        $x_1_7 = "DisableEnhancedNotifications" ascii //weight: 1
        $x_2_8 = {6a 5c 58 8b 4d fc 66 89 84 4d ?? ?? ff ff 6a 73 58 8b 4d fc 66 89 84 4d ?? ?? ff ff 6a 74}  //weight: 2, accuracy: Low
        $x_1_9 = {75 21 6a 02 58 c1 e0 00 8b 4d ?? 0f b7 04 01 83 f8 3a 75 0f}  //weight: 1, accuracy: Low
        $x_1_10 = {6a 02 58 6b c0 00 0f b7 84 05 ?? ?? ff ff 83 f8 25 74 09 c7 45 f8 01 00 00 00 eb 04}  //weight: 1, accuracy: Low
        $x_2_11 = {74 09 c7 45 f0 66 00 00 00 eb 07 c7 45 f0 73 00 00 00 ff 75 f0 ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Anunau_A_2147724551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Anunau.A!!Anunau.gen!A"
        threat_id = "2147724551"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Anunau"
        severity = "Critical"
        info = "Anunau: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 25 30 38 58 25 30 38 58 25 63 00}  //weight: 1, accuracy: High
        $x_1_2 = "Invmod of %d %% %d" ascii //weight: 1
        $x_1_3 = "plumber@cock.li" ascii //weight: 1
        $x_1_4 = "decryption,so you will pay me and them anyways.Please" ascii //weight: 1
        $x_1_5 = "call uninstall /nointeractive" ascii //weight: 1
        $x_1_6 = "DisableRoutinelyTakingAction" ascii //weight: 1
        $x_1_7 = "DisableEnhancedNotifications" ascii //weight: 1
        $x_2_8 = {6a 5c 58 8b 4d fc 66 89 84 4d ?? ?? ff ff 6a 73 58 8b 4d fc 66 89 84 4d ?? ?? ff ff 6a 74}  //weight: 2, accuracy: Low
        $x_1_9 = {75 21 6a 02 58 c1 e0 00 8b 4d ?? 0f b7 04 01 83 f8 3a 75 0f}  //weight: 1, accuracy: Low
        $x_1_10 = {6a 02 58 6b c0 00 0f b7 84 05 ?? ?? ff ff 83 f8 25 74 09 c7 45 f8 01 00 00 00 eb 04}  //weight: 1, accuracy: Low
        $x_2_11 = {74 09 c7 45 f0 66 00 00 00 eb 07 c7 45 f0 73 00 00 00 ff 75 f0 ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


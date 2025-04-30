rule Ransom_Win32_HydraCrypt_A_2147716793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HydraCrypt.A"
        threat_id = "2147716793"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HydraCrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 09 0f be c9 c1 c0 07 33 c1 42 8a 0a 84 c9 75 f1}  //weight: 2, accuracy: High
        $x_2_2 = {8a 01 3c 61 7c 15 3c 7a 7f 11 0f be c0 83 e8 54 6a 1a 99 5f f7 ff 80 c2 61 eb 17 3c 41 7c 15 3c 5a 7f 11 0f be c0 83 e8 34 6a 1a 99 5f f7 ff 80 c2 41 88 11 41 80 39 00 75 c6}  //weight: 2, accuracy: High
        $x_2_3 = {8b 54 24 04 33 c0 eb ?? 0f be c9 c1 c0 07 33 c1 42 8a 0a 84 c9}  //weight: 2, accuracy: Low
        $x_1_4 = "All Your files and documents were encrypted!" wide //weight: 1
        $x_1_5 = {68 74 74 70 3a 2f 2f 25 73 25 73 69 6d 67 2e 6a 70 67 00}  //weight: 1, accuracy: High
        $x_1_6 = {59 3a 5c 00 58 3a 5c 00 5a 3a 5c 00 48 3a 5c 00 47 3a 5c 00 46 3a 5c 00 45 3a 5c 00 44 3a 5c 00 43 3a 5c 00}  //weight: 1, accuracy: High
        $x_1_7 = "vssadmin.exe" ascii //weight: 1
        $x_1_8 = "<strong>YOUR_ID: %x%x</strong>" wide //weight: 1
        $x_1_9 = "%s.id_%x%x_email" wide //weight: 1
        $x_1_10 = "HELP_DECRYPT_YOUR_FILES" wide //weight: 1
        $x_1_11 = "delete shadows /all" ascii //weight: 1
        $x_1_12 = "shadow copy delete" ascii //weight: 1
        $x_1_13 = "NOT YOUR LANGUAGE" wide //weight: 1
        $x_1_14 = ".3g2.3gp.7z.ab4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_HydraCrypt_A_2147716796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HydraCrypt.A!!HydraCrypt.gen!A"
        threat_id = "2147716796"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HydraCrypt"
        severity = "Critical"
        info = "HydraCrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 09 0f be c9 c1 c0 07 33 c1 42 8a 0a 84 c9 75 f1}  //weight: 2, accuracy: High
        $x_2_2 = {8a 01 3c 61 7c 15 3c 7a 7f 11 0f be c0 83 e8 54 6a 1a 99 5f f7 ff 80 c2 61 eb 17 3c 41 7c 15 3c 5a 7f 11 0f be c0 83 e8 34 6a 1a 99 5f f7 ff 80 c2 41 88 11 41 80 39 00 75 c6}  //weight: 2, accuracy: High
        $x_2_3 = {8b 54 24 04 33 c0 eb ?? 0f be c9 c1 c0 07 33 c1 42 8a 0a 84 c9}  //weight: 2, accuracy: Low
        $x_1_4 = "All Your files and documents were encrypted!" wide //weight: 1
        $x_1_5 = {68 74 74 70 3a 2f 2f 25 73 25 73 69 6d 67 2e 6a 70 67 00}  //weight: 1, accuracy: High
        $x_1_6 = {59 3a 5c 00 58 3a 5c 00 5a 3a 5c 00 48 3a 5c 00 47 3a 5c 00 46 3a 5c 00 45 3a 5c 00 44 3a 5c 00 43 3a 5c 00}  //weight: 1, accuracy: High
        $x_1_7 = "vssadmin.exe" ascii //weight: 1
        $x_1_8 = "<strong>YOUR_ID: %x%x</strong>" wide //weight: 1
        $x_1_9 = "%s.id_%x%x_email" wide //weight: 1
        $x_1_10 = "HELP_DECRYPT_YOUR_FILES" wide //weight: 1
        $x_1_11 = "delete shadows /all" ascii //weight: 1
        $x_1_12 = "shadow copy delete" ascii //weight: 1
        $x_1_13 = "NOT YOUR LANGUAGE" wide //weight: 1
        $x_1_14 = ".3g2.3gp.7z.ab4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_HydraCrypt_B_2147722732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HydraCrypt.B"
        threat_id = "2147722732"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HydraCrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 50 08 8b 48 20 8b 00 81 79 0c 33 00 32 00 75 ef}  //weight: 1, accuracy: High
        $x_1_2 = {30 06 46 0f af c1 ba ?? ?? ?? ?? ff 4d 0c 4a 03 c2 83 7d 0c 00 77 e9}  //weight: 1, accuracy: Low
        $x_1_3 = {0f be c9 c1 c0 07 33 c1 42 8a 0a 84 c9 75 f1}  //weight: 1, accuracy: High
        $x_1_4 = {81 38 73 00 79 00 75 12 81 78 04 73 00 74 00 75 09 81 78 08 65 00 6d 00 74 0c}  //weight: 1, accuracy: High
        $x_1_5 = {30 07 47 0f af c1 ba ?? ?? ?? ?? ff 4d 0c 03 c2 40 40 83 7d 0c 00 77 e8}  //weight: 1, accuracy: Low
        $x_1_6 = {30 07 47 0f af c1 68 ?? ?? ?? ?? 5a ff 4d 0c 03 c2 40 83 7d 0c 00 77 e8}  //weight: 1, accuracy: Low
        $x_1_7 = {c1 c0 07 0f be c9 33 c1 42 8a 0a 84 c9 75 f1}  //weight: 1, accuracy: High
        $x_1_8 = {8a 07 32 c3 88 06 47 2b f2 49 75 f4}  //weight: 1, accuracy: High
        $x_1_9 = {81 38 73 00 79 00 75 0e 81 78 04 73 00 74 00 75 05 39 48 08 74 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_HydraCrypt_SA_2147775123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HydraCrypt.SA!MTB"
        threat_id = "2147775123"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HydraCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@tutanota.com" ascii //weight: 1
        $x_1_2 = "Files are encrypted" ascii //weight: 1
        $x_1_3 = "vssadmin.exe delete shadows /all /quiet" ascii //weight: 1
        $x_1_4 = "wmic shadowcopy delete" ascii //weight: 1
        $x_1_5 = "/C wbadmin delete catalog -quiet" ascii //weight: 1
        $x_1_6 = "READ_ME.hta" ascii //weight: 1
        $x_1_7 = "/C choice /C Y /N /D Y /T 1 & Del" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Ransom_Win32_HydraCrypt_PAA_2147779575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HydraCrypt.PAA!MTB"
        threat_id = "2147779575"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HydraCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All Your Files Has Been Encrypted" wide //weight: 1
        $x_1_2 = "wbadmin delete catalog -quiet" ascii //weight: 1
        $x_1_3 = "\\Decrypt-me.txt" wide //weight: 1
        $x_1_4 = "fuckyoufuckyou" ascii //weight: 1
        $x_1_5 = "pkey.txt" ascii //weight: 1
        $x_1_6 = "IDk.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_HydraCrypt_YAA_2147900193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HydraCrypt.YAA!MTB"
        threat_id = "2147900193"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HydraCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d f0 83 c1 01 33 4d f8 03 c1 88 45 ff 8b 55 f0 8a 45 ff 88 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_HydraCrypt_YAB_2147922134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HydraCrypt.YAB!MTB"
        threat_id = "2147922134"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HydraCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 e1 c1 ea 03 8d 14 92 03 d2 8b c1 2b c2 8a 54 04 10 30 14 39 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_HydraCrypt_NH_2147935367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HydraCrypt.NH!MTB"
        threat_id = "2147935367"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HydraCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {40 0c 03 05 ?? ?? ?? 00 51 03 d6}  //weight: 3, accuracy: Low
        $x_2_2 = {83 c0 c0 50 a1 ?? ?? ?? 00 8d 56 40 52}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_HydraCrypt_NIT_2147940413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HydraCrypt.NIT!MTB"
        threat_id = "2147940413"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HydraCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "files has been encrypted" ascii //weight: 2
        $x_2_2 = "wbadmin delete catalog -quiet" wide //weight: 2
        $x_2_3 = "bcdedit /set {default} recoveryenabled no" wide //weight: 2
        $x_2_4 = "vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 2
        $x_1_5 = "wmic shadowcopy delete" wide //weight: 1
        $x_1_6 = "get your files back" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


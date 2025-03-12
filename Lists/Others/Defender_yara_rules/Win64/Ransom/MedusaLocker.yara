rule Ransom_Win64_MedusaLocker_SIB_2147807750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MedusaLocker.SIB!MTB"
        threat_id = "2147807750"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MedusaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 00 4a 00 [0-10] 2e 00 65 00 78 00 65}  //weight: 2, accuracy: Low
        $x_1_2 = ".boot" ascii //weight: 1
        $x_5_3 = ".themida" ascii //weight: 5
        $x_10_4 = {48 01 d8 83 38 00 74 ?? 58 eb ?? 58 b9 ?? ?? ?? ?? 83 e9 ?? 48 01 c1 53 6a ?? 53 6a ?? 51 ff d0 5b b8 ?? ?? ?? ?? 48 01 d8 5d 5f 5e 5a 59 5b ff e0}  //weight: 10, accuracy: Low
        $x_10_5 = {8a 06 48 ff c6 88 07 48 ff c7 bb [0-4] 00 d2 75 ?? 8a 16 48 ff c6 10 d2 73 ?? 00 d2 75 ?? 8a 16 48 ff c6 10 d2 73 ?? 31 c0 00 d2 75 ?? 8a 16 48 ff c6 10 d2 0f 83 ?? ?? ?? ?? 00 d2 75 ?? 8a 16 48 ff c6 10 d2 11 c0 00 d2 75 ?? 8a 16 48 ff c6 10 d2 11 c0 00 d2 75 ?? 8a 16 48 ff c6 10 d2 11 c0 00 d2 75 ?? 8a 16 48 ff c6 10 d2 11 c0 74 ?? 57 89 c0 48 29 c7 8a 07 5f 88 07 48 ff c7 bb ?? ?? ?? ?? eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win64_MedusaLocker_YAA_2147893956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MedusaLocker.YAA!MTB"
        threat_id = "2147893956"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MedusaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 8d 79 08 41 8b c8 41 8b c2 83 e0 3f 2b c8 49 8b 47 08 48 8b 10 41 8b c0 48 d3 ca 49 33 d2 49 89 11 48 8b 15 ?? ?? ?? ?? 8b ca 83 e1 3f 2b c1 8a c8 49 8b 07 48 d3 ce 48 33 f2 48 8b 08 48 89 31 41 8b c8}  //weight: 2, accuracy: Low
        $x_1_2 = "SOFTWARE\\PAIDMEMES" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_MedusaLocker_AMLK_2147929200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MedusaLocker.AMLK!MTB"
        threat_id = "2147929200"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MedusaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 b8 02 00 00 00 48 8d 15 92 b2 06 00 48 8d 4c 24 50 e8 ?? ?? ?? ?? ?? 48 8d 44 24 50 48 83 7c 24 68 07 48 0f 47 44 24 50 66 01 38 48 8d 4c 24 50 48 83 7c 24 68 07 48 0f 47 4c 24 50 ff 15}  //weight: 2, accuracy: Low
        $x_1_2 = {48 8d 4c 24 50 48 83 7c 24 68 07 48 0f 47 4c 24 50 4c 8d 44 24 70 48 8d 55 80 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_MedusaLocker_DDZ_2147934181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MedusaLocker.DDZ!MTB"
        threat_id = "2147934181"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MedusaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 d2 48 8b c3 49 f7 f7 48 8b 06 0f b6 0c 0a 41 32 0c 18 88 0c 03 48 ff c3 48 3b dd 72 d2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_MedusaLocker_MLM_2147935595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MedusaLocker.MLM!MTB"
        threat_id = "2147935595"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MedusaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8d 55 c7 48 8d 4d 87 e8 a6 51 ff ff 33 d2 48 89 55 07 0f b6 44 15 ?? 30 03 48 ff c3 48 8b 55 07 48 ff c2 48 89 55 07 48 83 ef 01 75}  //weight: 5, accuracy: Low
        $x_1_2 = "[+][Encrypt] Encrypted:" wide //weight: 1
        $x_1_3 = "taskkill /f /im explorer.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_MedusaLocker_ZIN_2147935827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MedusaLocker.ZIN!MTB"
        threat_id = "2147935827"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MedusaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8d 53 40 48 8b cb e8 ?? ?? ?? ?? 48 8b c5 48 89 ab 80 00 00 00 0f b6 44 18 40 30 07 48 ff c7 48 ff 83 80 00 00 00 48 83 ee 01 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


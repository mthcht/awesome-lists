rule Ransom_Win64_Akira_PB_2147844371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Akira.PB!MTB"
        threat_id = "2147844371"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Akira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "akira" ascii //weight: 5
        $x_1_2 = "README.txt" ascii //weight: 1
        $x_1_3 = "---BEGIN PUBLIC KEY---" ascii //weight: 1
        $x_1_4 = "--encryption_path" ascii //weight: 1
        $x_1_5 = "--share_file" ascii //weight: 1
        $x_1_6 = "--encryption_percent" ascii //weight: 1
        $x_1_7 = "the internal infrastructure of your company is fully or partially dead" ascii //weight: 1
        $x_1_8 = "D:\\vcprojects\\akira\\asio\\include\\asio\\impl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Akira_AA_2147844607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Akira.AA!MTB"
        threat_id = "2147844607"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Akira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {42 0f b6 4c 0d ?? 83 e9 ?? 44 6b c1 ?? b8 09 04 02 81 41 f7 e8 41 03 d0 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 44 2b c0 41 83 c0 7f b8 09 04 02 81 41 f7 e8 41 03 d0 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 44 2b c0 46 88 44 0d ?? 49 ff c1 49 83 f9 ?? 72}  //weight: 2, accuracy: Low
        $x_2_2 = ".akira" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Akira_CT_2147845697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Akira.CT!MTB"
        threat_id = "2147845697"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Akira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "akira_readme.txt" ascii //weight: 2
        $x_1_2 = "Whatever who you are and what your title is if you're reading this it means the internal infrastructure of your company is fully or partially dead" ascii //weight: 1
        $x_1_3 = "all your backups - virtual, physical - everything that we managed to reach - are completely removed. Moreover, we have taken a great amount of your corporate data prior to encryption" ascii //weight: 1
        $x_1_4 = "Well, for now let's keep all the tears and resentment to ourselves and try to build a constructive dialogue" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Akira_GID_2147846282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Akira.GID!MTB"
        threat_id = "2147846282"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Akira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "readme-asldkas.txt" ascii //weight: 1
        $x_1_2 = "check-here.txt" ascii //weight: 1
        $x_1_3 = "all your backups - virtual, physical - everything that we managed to reach - are completely removed. Moreover, we have taken a great amount of your corporate data prior to encryption" ascii //weight: 1
        $x_1_4 = "Whatever who you are and what your title is if you're reading this it means the internal infrastructure of your company is fully or partially dead" ascii //weight: 1
        $x_1_5 = "Well, for now let's keep all the tears and resentment to ourselves and try to build a constructive dialogue" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win64_Akira_MKV_2147846874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Akira.MKV!MTB"
        threat_id = "2147846874"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Akira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 14 24 48 8b 94 24 18 01 00 00 8b 3c 24 03 7c 24 34 33 42 04 44 33 6a 0c 44 33 7a 14 44 33 72 18 33 6a 1c 33 72 20 33 7a 24 33 5a 28 44 33 5a 2c 44 33 42 38 33 4a 3c 89 44 24 70 8b 44 24 4c 41 03 c4 44 89 6c 24 58 33 42 08 44 8b 6c 24 18}  //weight: 5, accuracy: High
        $x_5_2 = "the internal infrastructure of your company is fully or partially dead, all your backups" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Akira_B_2147849309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Akira.B"
        threat_id = "2147849309"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Akira"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "akira_readme.txt" ascii //weight: 1
        $x_1_2 = "-----BEGIN PUBLIC KEY-----" ascii //weight: 1
        $x_1_3 = "Moreover, we have taken a great amount of your corporate data prior to encryption." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Akira_YAA_2147890058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Akira.YAA!MTB"
        threat_id = "2147890058"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Akira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e9 08 44 6b c1 22 41 f7 e8 41 03 d0 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 44 2b c0 b8 ?? ?? ?? ?? 41 83 c0 7f 41 f7 e8 41 03 d0 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 44 2b c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Akira_PA_2147894708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Akira.PA!MTB"
        threat_id = "2147894708"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Akira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".akira" ascii //weight: 1
        $x_1_2 = "akira_readme.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Akira_CCDR_2147895769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Akira.CCDR!MTB"
        threat_id = "2147895769"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Akira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c1 6b c8 ?? b8 ?? ?? ?? ?? f7 e9 03 d1 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 83 c1 ?? b8 ?? ?? ?? ?? f7 e9 03 d1 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 42 88 4c 05 c1 49 ff c0 49 83 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Akira_ZA_2147904750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Akira.ZA!MTB"
        threat_id = "2147904750"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Akira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ".akira" ascii //weight: 10
        $x_10_2 = "akira_readme.txt" ascii //weight: 10
        $x_1_3 = ".arika" ascii //weight: 1
        $x_1_4 = "https://akira" ascii //weight: 1
        $x_1_5 = "your corporate data prior to encryption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win64_Akira_AKR_2147911447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Akira.AKR!MTB"
        threat_id = "2147911447"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Akira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 8b c3 4d 8b d5 41 83 e5 3f 49 c1 fa 06 4e 8d 1c ed 00 00 00 00 4d 03 dd 41 8a 04 38 41 ff c1 4b 8b 8c d7 10 55 0f 00 49 03 c8 49 ff c0 42 88 44 d9 3e 49 63 c1 48 3b c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Akira_YAB_2147945775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Akira.YAB!MTB"
        threat_id = "2147945775"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Akira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".arika" wide //weight: 1
        $x_1_2 = ".vhdx" wide //weight: 1
        $x_10_3 = {48 89 ca 48 83 e2 03 44 8a 04 14 44 30 c0 88 04 0e 48 ff c1 4c 39 d1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Akira_ARAX_2147954750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Akira.ARAX!MTB"
        threat_id = "2147954750"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Akira"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 83 ec 78 48 89 d7 48 89 4c 24 38 48 8d 42 30 48 89 44 24 60 4c 8b 7a 10 48 8b 6a 28 48 8b 72 18 0f b6 5a 38 8a 42 40 88 44 24 2f 48 8b 0a 48 8b 42 08 48 89 44 24 40 4c 8b 72 20 8a 42 41 88 44 24 2e f6 44 24 2e 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Akira_I_2147959474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Akira.I"
        threat_id = "2147959474"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Akira"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {2e 61 6b 69 72 61 00}  //weight: 3, accuracy: High
        $x_1_2 = {2e 00 76 00 6d 00 65 00 6d 00 00 00 00 00 00 00 2e 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 00 73 00 75 00 62 00 76 00 6f 00 6c 00 00 00 2e 00}  //weight: 1, accuracy: High
        $x_1_4 = {2e 00 61 00 62 00 63 00 64 00 64 00 62 00 00 00 2e 00}  //weight: 1, accuracy: High
        $x_1_5 = ".sqlitedb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


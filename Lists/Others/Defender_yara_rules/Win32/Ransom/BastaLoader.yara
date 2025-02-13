rule Ransom_Win32_BastaLoader_A_2147841936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BastaLoader.A"
        threat_id = "2147841936"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BastaLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\rundll32.exe" wide //weight: 1
        $x_1_2 = "_c.dll,visibleentry" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BastaLoader_LK_2147842678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BastaLoader.LK!MTB"
        threat_id = "2147842678"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BastaLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 d8 83 c2 01 89 55 d8 8b 45 d8 3b 45 d0 7d 1a 8b 4d c0 03 4d d8 89 4d bc 8b 55 bc 52 8d 4d b0 e8 ?? ?? ?? ?? 89 45 a0 eb d5}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 40 68 00 30 00 00 ?? ?? ?? ?? ?? ?? 50 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 d4 8b 4d d0 8a 11 88 10 8b 45 fc 8b 08 89 4d cc 8b 55 fc 8b 02 83 c0 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_BastaLoader_LKA_2147845245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BastaLoader.LKA!MTB"
        threat_id = "2147845245"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BastaLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 70 70 5c 67 69 74 32 5c 55 6e 69 63 6f 64 65 20 52 65 6c 65 61 73 65 5c [0-32] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = "VisibleEntry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BastaLoader_MA_2147846019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BastaLoader.MA!MTB"
        threat_id = "2147846019"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BastaLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c4 08 85 c0 75 ?? 8b 45 fc 0f b6 48 5a 85 c9 75 ?? c7 45 f8 01 00 00 00 eb ?? c7 45 f8 00 00 00 00 8b 55 fc 8a 45 f8 88 42 5a 8b e5 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BastaLoader_SA_2147847880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BastaLoader.SA"
        threat_id = "2147847880"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BastaLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32" wide //weight: 1
        $x_10_2 = ".dll,visibleentry" wide //weight: 10
        $n_100_3 = "davsetcookie" wide //weight: -100
        $n_100_4 = "hgsportalsetupx86_c" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Ransom_Win32_BastaLoader_BA_2147849431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BastaLoader.BA!MTB"
        threat_id = "2147849431"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BastaLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 d6 66 8b 10 66 89 55 ?? 8b 45 ?? 83 c0 ?? 89 45 ?? 0f b7 4d ?? 8b 55 ?? c1 ea ?? 8b 45 ?? c1 e0 ?? 0b d0 03 ca 33 4d ?? 89 4d ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BastaLoader_NF_2147894599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BastaLoader.NF!MTB"
        threat_id = "2147894599"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BastaLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 14 01 33 c0 8b 15 ?? ?? ?? ?? 40 2b 05 ?? ?? ?? ?? 42 2b 05 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 31 0d ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 88 1c 02 ff 05 ?? ?? ?? ?? 81 fe ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BastaLoader_BE_2147899918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BastaLoader.BE!MTB"
        threat_id = "2147899918"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BastaLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1b c5 30 07 82 fe ?? ef 03 b7 ?? ?? ?? ?? 00 40 ?? 01 16}  //weight: 1, accuracy: Low
        $x_1_2 = {f8 01 2a bb ?? ?? ?? ?? 94 2b 92 ?? ?? ?? ?? fc 2a 7f ?? 34 ?? 20 02 d2 05 ?? ?? ?? ?? 21 ac fb ?? ?? ?? ?? 01 7c 71 ?? 1e 8d 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


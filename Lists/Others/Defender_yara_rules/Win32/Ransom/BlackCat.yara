rule Ransom_Win32_BlackCat_MK_2147809870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackCat.MK!MTB"
        threat_id = "2147809870"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackCat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "expand 32-byte k" ascii //weight: 1
        $x_1_2 = "Local\\RustBacktraceMutex" ascii //weight: 1
        $x_1_3 = {45 6c 65 76 61 74 69 6f 6e 3a 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 21 6e 65 77 3a 00 00 7b 33 45 35 46 43 37 46 39 2d 39 41 35 31 2d 34 33 36 37 2d 39 30 36 33 2d 41 31 32 30 32 34 34 46 42 45 43 37 7d}  //weight: 1, accuracy: High
        $x_1_4 = "\\explorer.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BlackCat_A_2147815777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackCat.A"
        threat_id = "2147815777"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackCat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 6e 61 62 6c 65 5f 65 73 78 69 5f 76 6d ?? 73}  //weight: 1, accuracy: Low
        $x_1_2 = {61 75 6c 74 5f 66 69 6c 65 5f 63 69 70 68 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BlackCat_AB_2147831517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackCat.AB"
        threat_id = "2147831517"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackCat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_5_2 = {83 c4 04 66 0f 6f 05 00 e8 09 00 0f 29 08 00 0f 29}  //weight: 5, accuracy: Low
        $x_5_3 = {83 c4 04 66 0f 6f 05 00 e8 0b 00 66 0f 7f 0b 00 0f 29 07 00 0f 29 0b 00 66 0f d4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BlackCat_ZZ_2147843505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackCat.ZZ"
        threat_id = "2147843505"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackCat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {8b 45 08 66 0f 6f 02 66 0f 38 00 00 66 0f 7f 01}  //weight: 10, accuracy: High
        $x_10_3 = {68 c0 1f 00 00 68 ?? ?? ?? ?? [0-7] 50 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BlackCat_SS_2147843847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackCat.SS!MTB"
        threat_id = "2147843847"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackCat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 d3 89 c8 31 d2 f7 f6 8b 45 f0 0f b6 04 10 89 da 30 04 0b 41 39 cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BlackCat_ZA_2147844399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackCat.ZA!MTB"
        threat_id = "2147844399"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackCat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "201"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {89 d3 89 c8 31 d2 f7 f6 8b 45 f0 0f b6 04 10 89 da 30 04 0b 41 39 cf}  //weight: 100, accuracy: High
        $x_100_3 = {8b 0e 8a 15 ?? ?? ?? ?? 88 14 01 ff 46 08 a2}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BlackCat_F_2147844842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackCat.F"
        threat_id = "2147844842"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackCat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 85 18 ff ff ff 74 65 20 6b c7 85 44 ff ff ff 32 2d 62 79 c7 85 68 ff ff ff 6e 64 20 33 ?? 85 48 ff ff ff 65 78 70 61}  //weight: 1, accuracy: Low
        $n_1_2 = {3d 43 01 00 00 7d}  //weight: -1, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Ransom_Win32_BlackCat_MA_2147846387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackCat.MA!MTB"
        threat_id = "2147846387"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackCat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "${NOTE_FILE_NAME}" ascii //weight: 5
        $x_2_2 = "_cipherkill_serviceskill_processesexclude" ascii //weight: 2
        $x_2_3 = "_network_discoveryenable_self" ascii //weight: 2
        $x_2_4 = "_wallpaperenable_esxi_vm_killenable_esxi_vm_snapshot" ascii //weight: 2
        $x_2_5 = "_killstrict_include_pathsesxi_vm_kill_excludesleep_restart" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BlackCat_ABC_2147851858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackCat.ABC!MTB"
        threat_id = "2147851858"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackCat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 f0 b9 59 17 b7 d1 f7 e1 89 f1 c1 ea 0d 69 c2 10 27 00 00 29 c1 0f b7 c1 c1 e8 02 69 c0 7b 14 00 00 c1 e8 11 6b f8 64 0f b7 84 00 e4 e3 60 00 29 f9 81 fe ff e0 f5 05 89 d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BlackCat_MMM_2147888796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackCat.MMM!MTB"
        threat_id = "2147888796"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackCat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 07 30 4f 01 0f b6 4c 24 2b 30 57 02 0f b6 54 24 2c 30 4f 03 0f b6 4c 24 2d 30 57 04 0f b6 54 24 2e 30 4f 05 0f b6 4c 24 2f 30 57 06 0f b6 54 24 ?? 30 4f 07 0f b6 4c 24 31 30 57 08}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 54 24 32 30 4f 09 0f b6 4c 24 33 30 57 0a 0f b6 54 24 34 30 4f 0b 0f b6 4c 24 35 30 57 0c 0f b6 54 24 36 30 4f 0d 0f b6 4c 24 ?? 30 57 0e 30 4f 0f 8b 4c 24 10 83 c7 10 83 c1 10 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


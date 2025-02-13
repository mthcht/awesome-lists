rule Ransom_Win32_Abucrosm_A_2147794734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Abucrosm.A"
        threat_id = "2147794734"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Abucrosm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files are encrypted" ascii //weight: 1
        $x_1_2 = "!! READ ME !!.txt" ascii //weight: 1
        $x_1_3 = ".cuba" ascii //weight: 1
        $x_1_4 = "cuba_support@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Abucrosm_2147794768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Abucrosm!MTB"
        threat_id = "2147794768"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Abucrosm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2a d3 80 c2 6d 88 15 ?? ?? ?? ?? 8b 7c 24 14 8b 4c 24 10 8a d1 2a 15 ?? ?? ?? ?? 88 54 24 0f 8b 3f 81 c7 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 3d ?? ?? ?? ?? 75 [0-96] 2b c3 83 c0 19 0f b7 d0 8b 44 24 14 8b f2 89 38}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7c 24 10 8a d8 2a 1d ?? ?? ?? ?? 8b 4c 24 20 80 c3 60 8b 54 24 1c 8b 3f 81 c7 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 83 f9 07 74 [0-80] 8a ca 2a c8 8d 41 08 8b 4c 24 10 89 39}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Abucrosm_AD_2147794769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Abucrosm.AD!MTB"
        threat_id = "2147794769"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Abucrosm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 ce 83 e6 03 75 0d 89 fb 66 01 da 6b d2 03 c1 ca 04 89 d7 30 10 40 e2 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Abucrosm_A_2147796148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Abucrosm.A!MTB"
        threat_id = "2147796148"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Abucrosm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c8 2b d1 83 c2 c3 8d 4a 28 02 c9 02 c1 8b 37 89 1d ?? ?? ?? ?? 81 c6 50 96 07 01 8a da 2a 5c 24 18 80 eb 1c 0f b6 cb 3b 4c 24 0c 72 17 0f b6 c8 66 01 0d ?? ?? ?? ?? 8b 4c 24 0c 8a d9 2a d8 80 eb 3d eb 04 8b 4c 24 0c 8a c3 89 37 2a c2 83 c7 04 2a c4 2c 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Abucrosm_SL_2147830934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Abucrosm.SL!MTB"
        threat_id = "2147830934"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Abucrosm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 8b 45 ?? 89 18 8b 45 ?? 03 45 ?? 03 45 ?? 03 45 ?? 89 45 ?? 6a ?? e8 ?? ?? ?? ?? 8b 5d ?? 2b d8 6a ?? e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 83 45 ?? ?? 83 45 ?? ?? 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


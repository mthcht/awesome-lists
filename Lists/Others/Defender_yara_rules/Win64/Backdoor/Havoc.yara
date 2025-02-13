rule Backdoor_Win64_Havoc_A_2147843838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Havoc.A!MTB"
        threat_id = "2147843838"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Havoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 63 d0 48 8b 45 20 48 01 d0 0f b6 08 8b 45 f8 48 63 d0 48 8b 45 10 48 01 d0 44 89 c2 31 ca 88 10 83 45 fc 01 83 45 f8 01 8b 45 f8 3b 45 18}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Havoc_D_2147845842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Havoc.D"
        threat_id = "2147845842"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Havoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {48 8b 1d ff 73 00 00 83 3d 50 60 00 00 ?? 75 0e e8 41 f9 ff ff 85 c0 74 05 e8 18 ee ff ff b9 ?? ?? 00 00 ff d3 eb e0}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Havoc_AD_2147894420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Havoc.AD!MTB"
        threat_id = "2147894420"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Havoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {41 83 e9 20 6b c0 21 45 0f b6 c9 49 ff c2 44 01 c8 45 8a 0a 85 d2 75 06 45 84 c9 41 80 f9 60 6b c0 21}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Havoc_B_2147898794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Havoc.B!MTB"
        threat_id = "2147898794"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Havoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 01 c0 83 c2 ?? 0f b6 00 30 01 48 83 c1 ?? 49 39 c9}  //weight: 2, accuracy: Low
        $x_2_2 = {4c 89 c0 ba ?? ?? ?? ?? 0f b6 00 30 01 48 83 c1 ?? 49 39 c9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Havoc_C_2147898795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Havoc.C!MTB"
        threat_id = "2147898795"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Havoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 63 d0 83 c0 ?? 4c 01 c2 0f b6 12 30 11 48 83 c1}  //weight: 2, accuracy: Low
        $x_2_2 = {4c 89 c2 b8 ?? ?? ?? ?? 0f b6 12 30 11 48 83 c1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Havoc_AJ_2147912275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Havoc.AJ!MTB"
        threat_id = "2147912275"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Havoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 98 ff c2 88 94 03 f0 00 00 00 31 c0 48 63 d0 ff c0 8a 54 14 30 41 30 55 00 49 ff c5 e9}  //weight: 2, accuracy: High
        $x_2_2 = {31 ca 88 50 fe 44 89 c2 45 01 c0 c0 fa 07 83 e2 1b 44 31 c2 41 31 d1 44 88 48 ff 48 39 44 24}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


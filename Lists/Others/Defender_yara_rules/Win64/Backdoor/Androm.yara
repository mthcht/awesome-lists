rule Backdoor_Win64_Androm_KK_2147837269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Androm.KK!MTB"
        threat_id = "2147837269"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 ba 00 00 02 00 41 b8 00 30 00 00 44 8d 49 40 ff 15 8b 32 1b 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 8d 0d cb 86 20 00 45 33 c9 45 33 c0 ff 15 ?? ?? ?? ?? 48 c7 44 24 28 00 00 00 00 45 33 c9 48 8b c8 c7 44 24 20 00 00 20 80 45 33 c0 48 8b d3 48 8b f8 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = "Release\\MFCLibrary3.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Androm_LKH_2147839503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Androm.LKH!MTB"
        threat_id = "2147839503"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 44 24 29 0f b6 44 24 20 c0 e0 02 c0 f9 04 0a c8 41 c0 e0 04 0f b6 c2 88 4c 24 28 c0 f8 02 49 8b cc c0 e2 06 41 0a c0 0a 54 24 23}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


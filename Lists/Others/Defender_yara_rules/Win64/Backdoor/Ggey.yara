rule Backdoor_Win64_Ggey_NI_2147777336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Ggey.NI!dha"
        threat_id = "2147777336"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Ggey"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 3f 00 01 00 48 8d 49 01 03 c2 0f b6 11 85 d2 75 ed 3d 0f 5a d8 38}  //weight: 1, accuracy: High
        $x_1_2 = {48 c7 c1 02 00 00 80 48 8d 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 75 ?? 48 8b ?? ?? ?? 48 8d}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 44 24 28 04 00 00 00 48 8d ?? ?? ?? ?? ?? 41 b9 04 00 00 00 48 89 44 24 20 45 33 c0 44 89 ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Ggey_2147777339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Ggey!MTB"
        threat_id = "2147777339"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Ggey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 81 f8 ff 00 00 00 41 0f b6 c0 4d 8d 49 01 41 0f 46 c0 44 8b c0 41 ff c0 0f b6 44 04 50 49 03 c3 0f b6 c8 0f b6 44 0c 50 43 32 44 0a ff 41 88 41 ff 48 83 ef 01 75 c8}  //weight: 1, accuracy: High
        $x_1_2 = "Patch Registry" wide //weight: 1
        $x_1_3 = "Delete Service" wide //weight: 1
        $x_1_4 = "Create Service" wide //weight: 1
        $x_1_5 = "Start Service" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


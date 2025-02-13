rule VirTool_Win32_Havokiz_E_2147841305_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Havokiz.E!MTB"
        threat_id = "2147841305"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Havokiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 8a 01 48 85 d2 75}  //weight: 1, accuracy: High
        $x_1_2 = {89 44 24 40 4c 89 44 24 48 44 89 4c 24 34 48 89 54 24 38 89 4c 24 30 e8}  //weight: 1, accuracy: High
        $x_1_3 = {48 31 db bb 4d 5a 00 00 48 ff c1 3e 66 3b 19 75}  //weight: 1, accuracy: High
        $x_1_4 = {0f b7 43 14 45 31 c0 48 8d 6c ?? ?? 48 89 ea}  //weight: 1, accuracy: Low
        $x_1_5 = {45 8b 48 04 48 01 c8 4d 01 c1 49 83 c0 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Havokiz_F_2147890082_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Havokiz.F!MTB"
        threat_id = "2147890082"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Havokiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 0e 00 00 00 52 89 85 4c ff ff ff 89 d8 f3 aa b9 28 00 00 00 ?? ?? ?? f3 aa b9}  //weight: 1, accuracy: Low
        $x_1_2 = {89 f7 f3 aa c7 04 24 00 00 00 00 ff 15 ?? ?? ?? ?? 51 89 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {89 74 24 08 c7 44 24 04 18 00 00 00 89 04 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


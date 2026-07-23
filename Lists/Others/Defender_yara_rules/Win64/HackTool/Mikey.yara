rule HackTool_Win64_Mikey_AHB_2147971002_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mikey.AHB!MTB"
        threat_id = "2147971002"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {c7 45 f0 6f 00 73 00 c7 45 f4 74 00 2e 00 c7 45 f8 65 00 78 00 c7 45 fc 65 00 00 00}  //weight: 30, accuracy: High
        $x_20_2 = "Local\\SysMonMutex_0" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_Mikey_SX_2147974317_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Mikey.SX!MTB"
        threat_id = "2147974317"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {35 2d 29 7a c7 85 ?? ?? ?? ?? 14 0e 7a 6b c7 85 ?? ?? ?? ?? 6a 74 6a 61 c7 85 ?? ?? ?? ?? 7a 0d 33 34 c7 85 ?? ?? ?? ?? 6c 6e 61 7a}  //weight: 30, accuracy: Low
        $x_10_2 = {41 80 f1 5a 48 8b ?? 10 48 ?? ?? 18 [0-5] 48 8d 41 01 48 89 ?? 10 48 8b ?? 48 83 [0-2] 0f}  //weight: 10, accuracy: Low
        $x_20_3 = "Local\\SysMonMutex_0" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


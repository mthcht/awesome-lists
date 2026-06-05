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


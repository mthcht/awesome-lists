rule HackTool_Win64_Disabler_AHB_2147956120_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Disabler.AHB!MTB"
        threat_id = "2147956120"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Disabler"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {48 8b f8 48 89 44 24 38 0f 57 c0 0f 11 00 0f 11 40 ?? 0f b6 03 48 c7 07}  //weight: 30, accuracy: Low
        $x_20_2 = "defender-disabler-ipc" ascii //weight: 20
        $x_10_3 = "defendnot\\cxx-shared" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule HackTool_Win64_CallBckHel_2147808771_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CallBckHel!MTB"
        threat_id = "2147808771"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CallBckHel"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b8 04 00 00 00 48 8d 15 [0-4] e8 [0-4] 85 c0 [0-6] 8b c7 48 3b 43 08 [0-6] 48 83 c3 18 48 3b de [0-6] 48 8b 5c 24 [0-2] 48 8b 74 24 [0-2] [0-16] 48 8b 03 48 8b 5c 24 [0-2] 48 83 e0 f0}  //weight: 1, accuracy: Low
        $x_1_2 = "ResetDCA" ascii //weight: 1
        $x_1_3 = "ResetDCW" ascii //weight: 1
        $x_1_4 = "k32enumdevicedrivers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


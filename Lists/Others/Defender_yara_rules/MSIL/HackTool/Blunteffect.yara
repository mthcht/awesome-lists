rule HackTool_MSIL_Blunteffect_DA_2147968704_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Blunteffect.DA!MTB"
        threat_id = "2147968704"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blunteffect"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {20 00 08 00 00 8d ?? 00 00 01 0a 02 03 16 03 8e 69 6f ?? 00 00 0a 02 6f ?? 00 00 0a 02 06 16 06 8e 69 6f ?? 00 00 0a 26 06 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


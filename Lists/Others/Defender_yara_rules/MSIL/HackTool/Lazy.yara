rule HackTool_MSIL_Lazy_MK_2147954244_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Lazy.MK!MTB"
        threat_id = "2147954244"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {04 03 7b 7b 00 00 04 20 00 00 00 01 41 29 00 00 00 03 03 7b ?? 00 00 04 1e 62 03 7b ?? 00 00 04 6f ?? 01 00 0a d2 60 7d}  //weight: 15, accuracy: Low
        $x_10_2 = {03 02 7b ad 00 00 04 61 0a 02 02 7b ad 00 00 04 1d 28 c6 00 00 06 06 61 7d ad 00 00 04}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


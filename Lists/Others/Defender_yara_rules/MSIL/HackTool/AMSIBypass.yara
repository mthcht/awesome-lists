rule HackTool_MSIL_AMSIBypass_SX_2147969229_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/AMSIBypass.SX!MTB"
        threat_id = "2147969229"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AMSIBypass"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {28 0b 00 00 06 26 06 7e ?? 00 00 04 17 28 01 00 00 2b 1f fe 28 09 00 00 0a 7e ?? 00 00 04 28 08 00 00 06 26}  //weight: 30, accuracy: Low
        $x_20_2 = {6a 58 28 0c 00 00 0a 28 0e 00 00 0a 13 04 11 04 16 16 28 0f 00 00 0a 12 02 09 7d ?? 00 00 04 12 02 25 7b ?? 00 00 04 1e}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


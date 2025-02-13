rule HackTool_MSIL_NetWeave_2147695316_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/NetWeave"
        threat_id = "2147695316"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetWeave"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Net-Weave Plugin" ascii //weight: 1
        $x_1_2 = "StopOnDisconnection" ascii //weight: 1
        $x_1_3 = "DDoSer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


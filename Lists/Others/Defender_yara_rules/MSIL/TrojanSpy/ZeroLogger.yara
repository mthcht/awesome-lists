rule TrojanSpy_MSIL_ZeroLogger_A_2147692588_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/ZeroLogger.A"
        threat_id = "2147692588"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZeroLogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "// ZeroLogger | Monitor | Logs \\" ascii //weight: 1
        $x_1_2 = "Zero Logger - You Got Logs!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


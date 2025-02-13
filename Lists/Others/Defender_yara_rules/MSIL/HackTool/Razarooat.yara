rule HackTool_MSIL_Razarooat_A_2147686569_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Razarooat.A"
        threat_id = "2147686569"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razarooat"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DDoS Attack" wide //weight: 1
        $x_1_2 = "SLOWSTART" wide //weight: 1
        $x_1_3 = "|LMmark|" wide //weight: 1
        $x_1_4 = "Razar RAT" wide //weight: 1
        $x_1_5 = "bitcoinSEND" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_MSIL_MatiexKeylogger_ZX_2147772083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MatiexKeylogger.ZX!MTB"
        threat_id = "2147772083"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MatiexKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FireFox Stub\\FireFox Stub\\obj\\Debug\\VNXT.pdb" ascii //weight: 1
        $x_1_2 = "<Module>" ascii //weight: 1
        $x_1_3 = "M-A-T-I-E-X--K-E-Y-L-O-G-E-R" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_MSIL_PhantomGate_SX_2147972023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PhantomGate.SX!MTB"
        threat_id = "2147972023"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PhantomGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {14 0a 06 14 28 03 00 00 0a 26 28 04 00 00 0a 02 6f 05 00 00 0a 2a}  //weight: 30, accuracy: High
        $x_10_2 = "PhantomGate" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


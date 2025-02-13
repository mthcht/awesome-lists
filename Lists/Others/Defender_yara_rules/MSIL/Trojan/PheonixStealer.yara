rule Trojan_MSIL_PheonixStealer_A_2147897772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PheonixStealer.A!MTB"
        threat_id = "2147897772"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PheonixStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 06 20 00 01 00 00 14 14 14 6f ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
        $x_1_3 = "GetTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


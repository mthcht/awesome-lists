rule Trojan_MSIL_VenusStealer_AGC_2147975026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VenusStealer.AGC!MTB"
        threat_id = "2147975026"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VenusStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5a 61 fe 0c 04 00 20 18 00 00 00 64 61 20 ff 00 00 00 5f fe 0e 06 00 09 fe 0c 05 00 09 fe 0c 05 00 91 fe 0c 06 00 61 d2 9c fe 0c 05 00 17 58}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


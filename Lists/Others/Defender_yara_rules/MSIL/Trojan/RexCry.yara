rule Trojan_MSIL_RexCry_DA_2147779754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RexCry.DA!MTB"
        threat_id = "2147779754"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RexCry"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Write path to file to encrypt" ascii //weight: 5
        $x_5_2 = "svchost.exe" ascii //weight: 5
        $x_5_3 = "PatternAt" ascii //weight: 5
        $x_5_4 = "FromBase64String" ascii //weight: 5
        $x_5_5 = "RexCry" ascii //weight: 5
        $x_1_6 = "MASFGKU" ascii //weight: 1
        $x_1_7 = "MASFUCK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Trojan_MSIL_InterStealer_RPX_2147892554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InterStealer.RPX!MTB"
        threat_id = "2147892554"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InterStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "##C##r#e##a#t##e#I##n#s##t#a##n#c##e#" wide //weight: 1
        $x_1_2 = "&Sy&&&&&" wide //weight: 1
        $x_1_3 = "&&tem.A&&&&&&&" wide //weight: 1
        $x_1_4 = "&&&&&cti&&&&&&" wide //weight: 1
        $x_1_5 = "&&&&va&&&&&&&" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


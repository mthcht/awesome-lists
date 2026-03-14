rule Trojan_MSIL_UnixStealer_AMTB_2147964802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/UnixStealer!AMTB"
        threat_id = "2147964802"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "UnixStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Unix Stealer" ascii //weight: 1
        $x_1_2 = "\\! UnixStealer\\Builder\\obj\\Release\\net6.0-windows\\Builder.pdb" ascii //weight: 1
        $x_1_3 = "Create your configured stealer executable" ascii //weight: 1
        $x_1_4 = "Save Stealer As" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


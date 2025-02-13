rule Worm_MSIL_Arcdoor_A_2147635737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Arcdoor.A"
        threat_id = "2147635737"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Arcdoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&botver=" wide //weight: 1
        $x_2_2 = "icmpflood" wide //weight: 2
        $x_1_3 = "EnableLUA" wide //weight: 1
        $x_2_4 = "bAntiParallelsDesktop" ascii //weight: 2
        $x_3_5 = "necrobotic" wide //weight: 3
        $x_3_6 = "bRARSpread" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}


rule Spammer_MSIL_Diloanamer_A_2147645366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:MSIL/Diloanamer.A"
        threat_id = "2147645366"
        type = "Spammer"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Diloanamer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSN_Spammer.My" ascii //weight: 1
        $x_1_2 = "Made by PaninoDanilo" wide //weight: 1
        $x_1_3 = "paninodanilo.altervista.org" wide //weight: 1
        $x_1_4 = "MSN_Spammer.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


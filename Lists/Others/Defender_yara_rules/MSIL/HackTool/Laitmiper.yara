rule HackTool_MSIL_Laitmiper_A_2147645477_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Laitmiper.A"
        threat_id = "2147645477"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Laitmiper"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSN_Freezer.My" ascii //weight: 1
        $x_1_2 = "Creato Da PaninoDanilo" wide //weight: 1
        $x_1_3 = "paninodanilo.altervista.org" wide //weight: 1
        $x_1_4 = "MSN_Freezer.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


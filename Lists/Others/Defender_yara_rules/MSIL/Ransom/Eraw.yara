rule Ransom_MSIL_Eraw_2147724454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Eraw"
        threat_id = "2147724454"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Eraw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "After the payment has been made, send 20 nude pictures of" ascii //weight: 5
        $x_5_2 = "tech support employees at 89755610@protonmail.com." ascii //weight: 5
        $x_5_3 = "SuccWare.exe" ascii //weight: 5
        $x_5_4 = "Send me your nudes first" wide //weight: 5
        $x_5_5 = "kil yorself fagot" wide //weight: 5
        $x_25_6 = "C:\\SuccWare\\SuccWare\\obj\\Debug\\SuccWare.pdb" ascii //weight: 25
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*))) or
            ((1 of ($x_25_*))) or
            (all of ($x*))
        )
}


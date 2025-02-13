rule Rogue_MSIL_Zeven_154230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:MSIL/Zeven"
        threat_id = "154230"
        type = "Rogue"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zeven"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mozilla/4.0 (compatible; 7AVINST 1.0; Windows; Trident/4.0)" wide //weight: 1
        $x_1_2 = "GetDefultAntivirus" ascii //weight: 1
        $x_1_3 = "GetReqopnceParametrs" ascii //weight: 1
        $x_1_4 = "Win7 AV. Protection of your computer" wide //weight: 1
        $x_1_5 = "\\Win7 AV\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


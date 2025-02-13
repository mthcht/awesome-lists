rule Worm_MSIL_Ferbot_A_2147639139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Ferbot.A"
        threat_id = "2147639139"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ferbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CANNOT CHABGE ZONE ID" wide //weight: 1
        $x_1_2 = "Making mutex!" wide //weight: 1
        $x_1_3 = "processkillah:" wide //weight: 1
        $x_1_4 = "Ive infected [" wide //weight: 1
        $x_1_5 = ":Steal pass error" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


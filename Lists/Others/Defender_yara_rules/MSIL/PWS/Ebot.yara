rule PWS_MSIL_Ebot_A_2147655738_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Ebot.A"
        threat_id = "2147655738"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ebot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pinlogger" wide //weight: 1
        $x_1_2 = "stealth" wide //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "mailaddresscollection" ascii //weight: 1
        $x_1_5 = "hookstruct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


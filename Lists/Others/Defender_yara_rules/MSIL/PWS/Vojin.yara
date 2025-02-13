rule PWS_MSIL_Vojin_A_2147686784_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Vojin.A"
        threat_id = "2147686784"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vojin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Syndicate Runescape Pinlog -" wide //weight: 1
        $x_1_2 = "Sending Skype Message:" wide //weight: 1
        $x_1_3 = "--- Syndicate Started ---" wide //weight: 1
        $x_1_4 = "Bank Found: Old School" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


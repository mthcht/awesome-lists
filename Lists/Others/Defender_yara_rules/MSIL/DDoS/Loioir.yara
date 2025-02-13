rule DDoS_MSIL_Loioir_A_2147708591_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:MSIL/Loioir.A"
        threat_id = "2147708591"
        type = "DDoS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loioir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58}  //weight: 1, accuracy: High
        $x_1_2 = {02 03 61 0c 08 1f 11 5a 1f 1b 5b 0c 07 1d 08 58}  //weight: 1, accuracy: High
        $x_1_3 = "ircBot.App_Config" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


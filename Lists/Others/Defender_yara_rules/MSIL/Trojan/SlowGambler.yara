rule Trojan_MSIL_SlowGambler_A_2147964205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SlowGambler.A!dha"
        threat_id = "2147964205"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SlowGambler"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 04 17 58 13 04 11 04 17 59 13 04 11 04 17 58 13 04 11 04 17 58 13 04 11 04 20 80 96 98 00 31 df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


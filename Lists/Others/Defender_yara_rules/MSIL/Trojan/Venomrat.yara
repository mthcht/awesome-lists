rule Trojan_MSIL_Venomrat_MCE_2147944917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Venomrat.MCE!MTB"
        threat_id = "2147944917"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Venomrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {fe 03 13 06 11 06 2c 0b 07 17 62 d2 1d 61 b4 0b 00 2b 07 00 07 17 62 d2 0b}  //weight: 2, accuracy: High
        $x_1_2 = "yssajwjhukgg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


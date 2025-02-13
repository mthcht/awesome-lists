rule Trojan_MSIL_Hercales_XZ_2147902977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hercales.XZ!MTB"
        threat_id = "2147902977"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hercales"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 b0 00 00 01 11 05 11 0a 74 10 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 75 10 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hercales_UL_2147909885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hercales.UL!MTB"
        threat_id = "2147909885"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hercales"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 07 02 58 20 06 78 ab 6c 11 00 59 11 01 61 61 11 0a 11 00 20 bb 22 1d 6a 61 11 01 59 5f 61 13 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


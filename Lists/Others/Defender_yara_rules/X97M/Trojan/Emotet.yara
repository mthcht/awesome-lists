rule Trojan_X97M_Emotet_DD_2147823853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:X97M/Emotet.DD"
        threat_id = "2147823853"
        type = "Trojan"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "urlm" ascii //weight: 1
        $x_1_2 = "on\",\"urldownloadtofil" ascii //weight: 1
        $x_1_3 = "jjccbb" ascii //weight: 1
        $x_1_4 = ".ocx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


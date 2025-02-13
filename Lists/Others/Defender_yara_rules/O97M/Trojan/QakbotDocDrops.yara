rule Trojan_O97M_QakbotDocDrops_A_2147770298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/QakbotDocDrops.A"
        threat_id = "2147770298"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "QakbotDocDrops"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


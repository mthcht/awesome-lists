rule Trojan_W97M_Chanitor_2147691388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:W97M/Chanitor"
        threat_id = "2147691388"
        type = "Trojan"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Chanitor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "91.220.131.114/upd/install" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


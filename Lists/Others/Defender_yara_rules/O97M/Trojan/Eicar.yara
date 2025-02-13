rule Trojan_O97M_Eicar_2147798107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Eicar"
        threat_id = "2147798107"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Eicar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "x5o!p%@ap[4pzx54(p^)7cc)7}$eicar-standard-antivirus-test-file!$h+h*\");" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


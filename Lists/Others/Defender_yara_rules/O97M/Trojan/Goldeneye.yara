rule Trojan_O97M_Goldeneye_A_2147718805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Goldeneye.A"
        threat_id = "2147718805"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Goldeneye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = " = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"" ascii //weight: 10
        $x_10_2 = ".Language = Chr(74) & Chr(83) & Chr(99) & Chr(114) & Chr(105) & Chr(112) & Chr(116)" ascii //weight: 10
        $x_10_3 = " = CreateObject(Chr(77) & Chr(83) & Chr(83) & Chr(99) & Chr(114) & Chr(105) & Chr(112) & Chr(116) & Chr(67) & Chr(111) & Chr(110)" ascii //weight: 10
        $x_10_4 = "docElement.text = 'AAAAAAAAAAA" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


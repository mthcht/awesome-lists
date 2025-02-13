rule Trojan_O97M_Mastdoc_A_2147742976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Mastdoc.A"
        threat_id = "2147742976"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Mastdoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\masterbox1.dll" ascii //weight: 2
        $x_2_2 = "\\pattern1.dll" ascii //weight: 2
        $x_1_3 = "ZipFolder" ascii //weight: 1
        $x_1_4 = "\\oleObject*.bin" ascii //weight: 1
        $x_1_5 = "\\UnzTmp" ascii //weight: 1
        $x_1_6 = "LoadLibraryW" ascii //weight: 1
        $x_1_7 = "FileFormat:=51" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


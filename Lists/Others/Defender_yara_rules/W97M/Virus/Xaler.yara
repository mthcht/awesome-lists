rule Virus_W97M_Xaler_A_2147691654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:W97M/Xaler.gen!A"
        threat_id = "2147691654"
        type = "Virus"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Xaler"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NormalTemplate.VBProject.vbcomponents.Item(\"ThisDocument\").CodeModule.InsertLines 1, keimeno" ascii //weight: 1
        $x_1_2 = "InStr(1, keimeno, \"'RELAX\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


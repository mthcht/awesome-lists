rule Virus_W97M_Ostrich_A_2147693011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:W97M/Ostrich.gen!A"
        threat_id = "2147693011"
        type = "Virus"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Ostrich"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".VBProject.VBComponents.Item(&O1).CodeModule" ascii //weight: 1
        $x_1_2 = ": Do While .CountOfLines > &O0: .DeleteLines 1: Loop: End With" ascii //weight: 1
        $x_1_3 = ", &O1, .CountOfLines, 1, False, False, False) Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


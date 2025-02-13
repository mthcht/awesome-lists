rule Virus_W97M_Thus_GB_2147697342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:W97M/Thus.GB"
        threat_id = "2147697342"
        type = "Virus"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Thus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MyCode = ThisDocument.VBProject.VBComponents(1).CodeModule.Lines(1, 20)" ascii //weight: 1
        $x_1_2 = "Set Host = NormalTemplate.VBProject.VBComponents(1).CodeModule" ascii //weight: 1
        $x_1_3 = "If ThisDocument = NormalTemplate Then" ascii //weight: 1
        $x_1_4 = "If .Lines(1, 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_W97M_Thus_GC_2147707185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:W97M/Thus.GC"
        threat_id = "2147707185"
        type = "Virus"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Thus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 69 74 68 20 48 6f 73 74 0d 0a 20 20 20 20 49 66 20 2e 4c 69 6e 65 73 28 31 2c 20 31 29 20 3c 3e 20 22 27 4d 69 63 72 6f 2d 56 69 72 75 73 22 20 54 68 65 6e 0d 0a 20 20 20 20 0d 0a 20 20 20 20 20 20 20 20 2e 44 65 6c 65 74 65 4c 69 6e 65 73 20 31 2c 20 2e 43 6f 75 6e 74 4f 66 4c 69 6e 65 73 0d 0a}  //weight: 1, accuracy: High
        $x_1_2 = "Ourcode = ThisDocument.VBProject.VBComponents(1).CodeModule.Lines(1, 100)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_W97M_Thus_A_2147707186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:W97M/Thus.gen!A"
        threat_id = "2147707186"
        type = "Virus"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Thus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= ThisDocument.VBProject.VBComponents(1).CodeModule.Lines(1," ascii //weight: 1
        $x_1_2 = "= NormalTemplate.VBProject.VBComponents(1).CodeModule" ascii //weight: 1
        $x_1_3 = "If .Lines(1, 1)" ascii //weight: 1
        $x_1_4 = ".DeleteLines 1, .CountOfLines" ascii //weight: 1
        $x_1_5 = ".InsertLines 1," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


rule Virus_W97M_Linear_2147584579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:W97M/Linear"
        threat_id = "2147584579"
        type = "Virus"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Linear"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4f 70 65 6e 20 22 [0-16] 2e 63 6f 6d 22 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20}  //weight: 1, accuracy: Low
        $x_1_2 = "Print #" ascii //weight: 1
        $x_1_3 = "Close #" ascii //weight: 1
        $x_1_4 = "= Shell(\"" ascii //weight: 1
        $x_1_5 = ".VBProject.VBComponents(1).CodeModule.insertlines" ascii //weight: 1
        $x_1_6 = ".VBProject.VBComponents(1).CodeModule.deletelines" ascii //weight: 1
        $x_1_7 = "Application.ShowVisualBasicEditor = 0" ascii //weight: 1
        $x_1_8 = "Application.EnableCancelKey = 0" ascii //weight: 1
        $x_1_9 = "Private Sub ViewVBCode()" ascii //weight: 1
        $x_1_10 = "Private Sub ToolsMacro()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


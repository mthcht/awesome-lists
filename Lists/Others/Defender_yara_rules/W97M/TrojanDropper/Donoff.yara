rule TrojanDropper_W97M_Donoff_A_2147696737_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:W97M/Donoff.A"
        threat_id = "2147696737"
        type = "TrojanDropper"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ActiveDocument.Range.Text" ascii //weight: 1
        $x_1_2 = "Open tmpd For Binary Lock Write As" ascii //weight: 1
        $x_1_3 = "While (bWritten < Len(lpTextData))" ascii //weight: 1
        $x_1_4 = "Symbol = Mid(lpTextData, bWritten," ascii //weight: 1
        $x_1_5 = {50 75 74 20 [0-16] 20 43 42 79 74 65 28 53 79 6d 62 6f 6c 29}  //weight: 1, accuracy: Low
        $x_1_6 = "bWritten = bWritten + " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


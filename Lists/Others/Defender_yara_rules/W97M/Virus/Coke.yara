rule Virus_W97M_Coke_A_2147692502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:W97M/Coke.A"
        threat_id = "2147692502"
        type = "Virus"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Coke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\cOcAinE.sRC >nUL" ascii //weight: 1
        $x_1_2 = "C:\\W32coKe.exe >NUl" ascii //weight: 1
        $x_1_3 = "del c:\\w32cokE.Ex >Nul" ascii //weight: 1
        $x_1_4 = ", \"N C:\\W32COKE.EX\"" ascii //weight: 1
        $x_1_5 = ", \"E 0100 4D 5A 50 00 02 00 00 00 04 00 0F 00 FF FF 00 00\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


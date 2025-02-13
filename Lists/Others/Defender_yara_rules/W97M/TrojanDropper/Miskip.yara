rule TrojanDropper_W97M_Miskip_A_2147707261_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:W97M/Miskip.A!dha"
        threat_id = "2147707261"
        type = "TrojanDropper"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Miskip"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CheckFile = CheckFile Xor MacrosArray(I)" ascii //weight: 1
        $x_1_2 = "StartMacros = DocSize - (MacrosSize + 4)" ascii //weight: 1
        $x_1_3 = "CheckValue = CheckFile(MacrosArray(), MacrosSize)" ascii //weight: 1
        $x_1_4 = "File = Folder & \"\\\" & \"MSWord.exe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


rule TrojanDownloader_O97M_Zinunlate_A_2147716850_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Zinunlate.A"
        threat_id = "2147716850"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Zinunlate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "s(74, \"1ez7atn8lau7lin\", 41)) <> 0" ascii //weight: 1
        $x_1_2 = "s(267, \"tjciisbStFyOtp.Smcigeeernl\", 47))" ascii //weight: 1
        $x_1_3 = "s(78, \"e.fntZerIieion:d\", 167)" ascii //weight: 1
        $x_1_4 = "s(42, \"htrWe.iSlSpcl\", 95))" ascii //weight: 1
        $x_1_5 = "eemhpms)ea$e]tdue)l./.rIwDaNEtt(/cSelz,Steo.b$FeptSmN)l;)Gyll =abuntPbn8-cm.td t;ntfl: F/c$eW/biO-o1exTe'uoy(ii hhcaejfit:ec.e.l(.esei-[mCn'.ajl7O(pNtaWe(te)l:SictfNenip.Ow7w" ascii //weight: 1
        $x_1_6 = "s(51, \"pec.lihStlrSW\", 125))" ascii //weight: 1
        $x_1_7 = "(103, 99, \"pec.lihStlrSW\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


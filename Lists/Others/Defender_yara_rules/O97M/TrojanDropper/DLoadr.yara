rule TrojanDropper_O97M_DLoadr_P_2147749706_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/DLoadr.P!MSR"
        threat_id = "2147749706"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "DLoadr"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_9_1 = "h0 = \"mt\" + \"h.9\" + \"0/9\" + \"6:o\" + \"t.su.spu\" + \"org/\" + \"/:pt\" + \"th " ascii //weight: 9
        $x_1_2 = "c0 = \"aT\" + \"h\" + \"Sm" ascii //weight: 1
        $x_10_3 = "s0 (\"m\") + \"Sh\" + (\"T\") + \"a h\" + (\"t\") + (\"t\") + \"p://group\" + (\"s\") + \".u\" + (\"s\") + \".to:69/03.h\" + (\"t\") + (\"m\")" ascii //weight: 10
        $x_9_4 = "s0 (\"m\") + (\"s\") + (\"h\") + (\"t\") + (\"a\") + (\" \") + (\"h\") + (\"t\") + (\"t\") + (\"p\") + (\"s\") + (\":\") + (\"/\") + (\"/\") + (\"t\")" ascii //weight: 9
        $x_1_5 = "Set d0 = GetObject(\"WiNmGmTs:{ImPeRsOnAtIoNlEvEl=ImPeRsOnAtE}!\\\\.\\RoOt\\CiMv2\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_9_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}


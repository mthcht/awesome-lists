rule TrojanDropper_O97M_Dwyad_A_2147716898_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Dwyad.A"
        threat_id = "2147716898"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dwyad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "For Each OptiplexopticoreavdvatagesessionserveringleadTWOMoneta In ActiveDocument.Paragraphs" ascii //weight: 1
        $x_1_2 = "While (OptiplexopticoreavdvatagesessionserveringleadTWOBizancjum < Len(OptiplexopticoreavdvatagesessionserveringleadTRZYExta1))" ascii //weight: 1
        $x_1_3 = "+ \"H\" & Mid(OptiplexopticoreavdvatagesessionserveringleadTRZYExta1, OptiplexopticoreavdvatagesessionserveringleadTWOBizancjum, 2)" ascii //weight: 1
        $x_1_4 = "OptiplexopticoreavdvatagesessionserveringleadONEKotleta = Environ(\"ALLUSERSPROFILE\") + \"\\MemSys\" + Chr(LRandomNumber) + Chr(LRandomNumber2)" ascii //weight: 1
        $x_1_5 = "Difdmapqemkh47 = Shell(Xjeqjpewkjq32, 0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


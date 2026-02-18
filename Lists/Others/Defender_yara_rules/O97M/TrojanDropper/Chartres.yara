rule TrojanDropper_O97M_Chartres_A_2147963220_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Chartres.A!MTB"
        threat_id = "2147963220"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Chartres"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"M\" + \"S\" + \"X\" + \"M\" + Chr(196 - 120) + \"2\" + \".\" + \"D\" + \"O\" + \"M\" + \"D\" + \"o\" + \"c\" + \"u\" + \"m\" + \"e\" + Chr(258 - 148) + \"t\"" ascii //weight: 1
        $x_1_2 = "= \"b\" + \"i\" + \"n\" + \".\" + \"b\" + \"a\" + \"s\" + \"e\" + \"6\" + \"4\"" ascii //weight: 1
        $x_1_3 = "= \"S\" + \"h\" + \"e\" + \"l\" + \"l\" + \".\" + \"A\" + \"p\" + \"p\" + \"l\" + \"i\" + Chr(236 - 137) + Chr(295 - 198) + \"t\" + \"i\" + Chr(238 - 127) + \"n\"" ascii //weight: 1
        $x_1_4 = "= \"@\" + \"e\" + \"c\" + \"h\" + \"o\" + \" \" + \"o\" + \"f\" + Chr(208 - 106)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


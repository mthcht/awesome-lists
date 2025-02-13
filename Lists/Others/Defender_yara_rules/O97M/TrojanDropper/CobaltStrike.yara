rule TrojanDropper_O97M_CobaltStrike_API_2147830776_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/CobaltStrike.API!MTB"
        threat_id = "2147830776"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getparagraphopendllpathforbinaryas1put1bclose1" ascii //weight: 1
        $x_1_2 = "etdsbase64decodexglwagxwyxbplmrsbaflnpbase64decodexgnhy2hllvhkre5tsldqrkhelnrtca" ascii //weight: 1
        $x_1_3 = "namefnzstasstatbase64decodexe1py3jvc29mdfxuzwftc1xjdxjyzw50etdsendifend" ascii //weight: 1
        $x_1_4 = "getwpfori0touboundddistrreversedinextisjoindgetparagraphstrconvbase64decodesvbfromunicodeendfunction" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


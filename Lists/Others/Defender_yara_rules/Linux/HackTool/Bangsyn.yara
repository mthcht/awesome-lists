rule HackTool_Linux_Bangsyn_A_2147824980_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Bangsyn.A!xp"
        threat_id = "2147824980"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Bangsyn"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "syntax: ./bangsyn ip port time" ascii //weight: 1
        $x_2_2 = "bangsyn.c" ascii //weight: 2
        $x_1_3 = "dosynpacket" ascii //weight: 1
        $x_1_4 = "santong syn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


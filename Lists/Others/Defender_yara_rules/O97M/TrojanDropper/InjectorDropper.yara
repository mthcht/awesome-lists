rule TrojanDropper_O97M_InjectorDropper_SK_2147752684_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/InjectorDropper.SK!MTB"
        threat_id = "2147752684"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "InjectorDropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\", \"vnp.dll\", \"" ascii //weight: 5
        $x_1_2 = "Private Sub Document_Open()" ascii //weight: 1
        $x_1_3 = "delaymailto = Passant.beastmode(0)" ascii //weight: 1
        $x_1_4 = "Call tpl_vid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}


rule TrojanDropper_O97M_CrimsonRAT_YA_2147753857_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/CrimsonRAT.YA!MTB"
        threat_id = "2147753857"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "CrimsonRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell path_Nava_file & \"xe\"" ascii //weight: 1
        $x_1_2 = "fldr_Nava_name = Environ$(\"ALLUSERSPROFILE\")" ascii //weight: 1
        $x_1_3 = "Open path_Nava_file & \"xe\" For Binary Access Write" ascii //weight: 1
        $x_1_4 = "btsSocda7(linNava) = CByte(vl)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


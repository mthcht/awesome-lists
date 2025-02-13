rule TrojanDownloader_O97M_Powloadsh_A_2147734534_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powloadsh.A"
        threat_id = "2147734534"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powloadsh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub Auto_Open()" ascii //weight: 1
        $x_1_2 = "spath = Environ(\"temp\") &" ascii //weight: 1
        $x_1_3 = "spath = spath & \".p\" & \"s1\"" ascii //weight: 1
        $x_1_4 = "Shell \"po\" & \"wersh\" & \"ell -Exe\" & \"cutionP\" & \"olicy B\" & \"ypass -f\" & \"ile \" & spath," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


rule TrojanDownloader_O97M_Pyark_PF_2147764827_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Pyark.PF!MTB"
        threat_id = "2147764827"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Pyark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "files.000webhost.com" ascii //weight: 1
        $x_1_2 = "= \"C:\\ProgramData" ascii //weight: 1
        $x_1_3 = "= local_file & \"\\NisSrv.bat" ascii //weight: 1
        $x_1_4 = "= local_file & \"\\Service.lnk" ascii //weight: 1
        $x_1_5 = "= Environ(\"APPDATA\")" ascii //weight: 1
        $x_1_6 = "Usuario = \"x3543sd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


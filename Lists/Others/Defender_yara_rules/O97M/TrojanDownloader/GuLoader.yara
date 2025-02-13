rule TrojanDownloader_O97M_GuLoader_PD_2147769859_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/GuLoader.PD!MTB"
        threat_id = "2147769859"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "exe\" -Destination" ascii //weight: 1
        $x_1_2 = "\"${enV`:appdata}" ascii //weight: 1
        $x_1_3 = "\"c\"&CHAR(109)&CHAR(100)&CHAR(32)&CHAR(47)&CHAR(99)&CHAR(32)&CHAR(112)&CHAR(111)&\"wer^she\"&CHAR(108)&CHAR(108)&CHAR(32)&\"" ascii //weight: 1
        $x_1_4 = "stARt`-slE`Ep 25;" ascii //weight: 1
        $x_1_5 = "('.'+'/sw\"&CHAR(46)&\"exe')\")" ascii //weight: 1
        $x_1_6 = "ttps://tinyurl.com/y5dsc4ag" ascii //weight: 1
        $x_1_7 = "('Down'+'loadFile')" ascii //weight: 1
        $x_1_8 = "\"Invoke\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


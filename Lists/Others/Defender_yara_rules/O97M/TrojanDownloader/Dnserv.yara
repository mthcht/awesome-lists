rule TrojanDownloader_O97M_Dnserv_2147731930_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dnserv"
        threat_id = "2147731930"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dnserv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Environ(\"userp\" & \"rofile\") & \"\\.or\" & \"acleServices\\svshost_serv.\" & \"e\" & \"x\" & \"e\"" ascii //weight: 1
        $x_1_2 = "= Environ(\"userp\" & \"rofile\") & \"\\.oracleServices\\svshost_serv.\" & \"d\" & \"o\" & \"c\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


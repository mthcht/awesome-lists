rule TrojanDownloader_O97M_Dokgirat_A_2147729536_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Dokgirat.A"
        threat_id = "2147729536"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dokgirat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Y21k LmV4ZQ==" ascii //weight: 1
        $x_1_2 = "L2Mgc3RhcnQ=" ascii //weight: 1
        $x_1_3 = "a21icjEubml0ZXNicjEub3Jn" ascii //weight: 1
        $x_1_4 = "L1VzZXJGaWxlcy9GaWxlL2ltYWdlL2hvbWUuaHRtbA==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


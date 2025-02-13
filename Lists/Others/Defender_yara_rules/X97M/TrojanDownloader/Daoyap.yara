rule TrojanDownloader_X97M_Daoyap_A_2147691680_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:X97M/Daoyap.gen!A"
        threat_id = "2147691680"
        type = "TrojanDownloader"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Daoyap"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://" ascii //weight: 1
        $x_1_2 = "savetofile" ascii //weight: 1
        $x_1_3 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_4 = "CreateObject(\"Adodb.Stream\")" ascii //weight: 1
        $x_1_5 = "payload.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


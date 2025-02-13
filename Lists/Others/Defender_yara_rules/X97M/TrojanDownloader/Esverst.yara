rule TrojanDownloader_X97M_Esverst_A_2147706349_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:X97M/Esverst.A"
        threat_id = "2147706349"
        type = "TrojanDownloader"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Esverst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "22=vswwk\"))" ascii //weight: 1
        $x_1_2 = "(\"h{h1\"))" ascii //weight: 1
        $x_1_3 = "CreateObject(\"WScript.Shell\").Run Environ(\"temp\") &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


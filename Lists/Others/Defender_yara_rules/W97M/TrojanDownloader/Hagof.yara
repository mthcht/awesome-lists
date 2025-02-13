rule TrojanDownloader_W97M_Hagof_A_2147694571_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Hagof.gen!A"
        threat_id = "2147694571"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Hagof"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If 1 = 1 Then: mcafee = Environ(mcafee)" ascii //weight: 1
        $x_1_2 = "If 1 = 1 Then: ADS.Write XML.responseBody" ascii //weight: 1
        $x_1_3 = "If 1 = 1 Then: Wikipedia = \"h\" & \"tt\" & _" ascii //weight: 1
        $x_1_4 = "If 1 = 1 Then: Shell Wikipedia(\"SR\"), vbNormalFocus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


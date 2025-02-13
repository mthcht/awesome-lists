rule TrojanDownloader_W97M_Nodpulru_A_2147689074_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:W97M/Nodpulru.A"
        threat_id = "2147689074"
        type = "TrojanDownloader"
        platform = "W97M: Word 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Nodpulru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MyHttps.Open \"POST\", \"https://pulinkovo.ru/index.php\", False" ascii //weight: 1
        $x_1_2 = "MyHttps.setRequestHeader \"Referer\", \"nod-huisoset.sk\"" ascii //weight: 1
        $x_1_3 = "TempFileName = Environ(\"APPDATA\")" ascii //weight: 1
        $x_1_4 = "TempFileName = TempFileName & \"/macrofile.exe\"" ascii //weight: 1
        $x_1_5 = "Shell TempFileName, vbNormalNoFocus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


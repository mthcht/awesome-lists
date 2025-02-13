rule TrojanDownloader_X97M_Powdow_SG_2147828869_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:X97M/Powdow.SG!MSR"
        threat_id = "2147828869"
        type = "TrojanDownloader"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Powdow"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bookstore.neu.edu.tr/KGB Numaralari ve Gecerlilik Tarihleri.xlsx" ascii //weight: 1
        $x_1_2 = "myURL = cop & \"\\Temp\" & \"\\file.xlsx" ascii //weight: 1
        $x_1_3 = "Workbooks.Open(FileName:=myURL, Password:=1234)" ascii //weight: 1
        $x_1_4 = "objNode.DataType = \"bin.base64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


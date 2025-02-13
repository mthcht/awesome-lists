rule TrojanDownloader_O97M_Hubusi_A_2147688749_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Hubusi.A"
        threat_id = "2147688749"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hubusi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sAppData = Environ(\"USERPROFILE\")" ascii //weight: 1
        $x_1_2 = "Set bStrm = CreateObject(\"Adodb.Stream\")" ascii //weight: 1
        $x_1_3 = "xHttp = CreateObject(\"Microsoft.XMLHTTP\")" ascii //weight: 1
        $x_1_4 = "Shell sAppData & \"\\FFFd.COM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


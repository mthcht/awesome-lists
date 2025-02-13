rule TrojanDownloader_O97M_Kudsica_A_2147690123_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Kudsica.A"
        threat_id = "2147690123"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Kudsica"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Print #FileNumber, \"$down = N\" & \"ew\" & \"-\" & Chr(79) & \"bject Sy\" & \"stem.\" & Chr(78) & \"et.\" & Chr(87) & \"eb\" & \"Cli\" & \"ent;\"" ascii //weight: 1
        $x_1_2 = "MY_FILDIR = \"c:\\windows\\temp\" + \"\\adobeacd-update.\" & Chr(118) & \"b\" & \"s" ascii //weight: 1
        $x_1_3 = "Print #FileNumber, \"$file1.Attributes = $file1.Attributes -bxor [System.IO.FileAttributes]::Hidden" ascii //weight: 1
        $x_1_4 = "MY_FILEDIR = \"c:\\Users\\\" + USER + \"\\AppData\\Local\\Temp" ascii //weight: 1
        $x_1_5 = "Print #FileNumber, \"strFileURL = \" + Chr(34) + \"http:" ascii //weight: 1
        $x_1_6 = "Print #FileNumber, \"Set objXMLHTTP = CreateObject(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


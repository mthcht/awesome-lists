rule TrojanDownloader_O97M_Endoc_YR_2147759889_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Endoc.YR!MTB"
        threat_id = "2147759889"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Endoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "owershell.exe -Command IEX (New-Object('Net.WebClient')).'DoWnlo" ascii //weight: 1
        $x_1_2 = "spacemantra.biz/blyat" ascii //weight: 1
        $x_1_3 = "dsTrInG'('" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Endoc_VS_2147816338_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Endoc.VS!MSR"
        threat_id = "2147816338"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Endoc"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "imgsrc = \"http://80.78.25.223/walter.png\"" ascii //weight: 1
        $x_1_2 = "batchFile = \"C:\\Temp\\walter.bat\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Endoc_PGI_2147898431_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Endoc.PGI!MTB"
        threat_id = "2147898431"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Endoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/c powershell -command" ascii //weight: 1
        $x_1_2 = "DownloadFile" ascii //weight: 1
        $x_1_3 = "https://raw.githubusercontent.com/aybiota/mpbh33775/gh-pages/g9wl5dp.ttf" ascii //weight: 1
        $x_1_4 = {25 74 6d 70 25 5c 5c [0-10] 2e 6a 61 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanDownloader_O97M_Malshelcpt_DD_2147742747_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Malshelcpt.DD"
        threat_id = "2147742747"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Malshelcpt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Environ(\"TEMP\") & \"\\13.xlsx" ascii //weight: 1
        $x_1_2 = "Environ(\"TEMP\") '& \"\\UnzTmp" ascii //weight: 1
        $x_1_3 = "ADATA + \"\\exchange2.dll" ascii //weight: 1
        $x_1_4 = "Set oApp = CreateObject(\"Shell.Application\")" ascii //weight: 1
        $x_1_5 = "oApp.Namespace(ZipFolder).CopyHere oApp.Namespace(ZipName).items.Item(\"xl\\embeddings\\oleObject1.bin\")" ascii //weight: 1
        $x_1_6 = "ReadAndWriteExtractedBinFile ZipFolder + \"\\oleObject1.bin\", nm, size, num" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


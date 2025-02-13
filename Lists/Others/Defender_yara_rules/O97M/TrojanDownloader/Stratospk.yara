rule TrojanDownloader_O97M_Stratospk_A_2147735808_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Stratospk.A"
        threat_id = "2147735808"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Stratospk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Replace((\"hhhfda.gov.pk/assets/uploads/GalleryAlbumImages/Adobe" ascii //weight: 1
        $x_1_2 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_3 = "Replace((\"abcbitsabcadmin /transabcfer myFabcile /downlabcoad /priorabcity norabcmal \"), \"abc\", \"\") & gggg & \" \" & trfutyjnih, Replace(\"050\", \"50\", \"\"), Replace(\"Fa50lse\", \"50\", \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


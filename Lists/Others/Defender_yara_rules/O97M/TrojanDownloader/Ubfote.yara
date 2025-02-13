rule TrojanDownloader_O97M_Ubfote_A_2147743262_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Ubfote.A!MSR"
        threat_id = "2147743262"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Ubfote"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Private Sub Document_Open()" ascii //weight: 1
        $x_1_2 = "sCmdLine = Environ(\"windir\")" ascii //weight: 1
        $x_1_3 = {73 43 6d 64 4c 69 6e 65 20 3d 20 73 43 6d 64 4c 69 6e 65 20 [0-11] 54 65 78 74 42 6f 78 31 2e 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_4 = "Shell(sCmdLine, vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


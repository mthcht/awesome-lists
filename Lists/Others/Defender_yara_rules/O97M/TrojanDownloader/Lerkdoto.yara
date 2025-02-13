rule TrojanDownloader_O97M_Lerkdoto_A_2147688540_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Lerkdoto.A"
        threat_id = "2147688540"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Lerkdoto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ret = DesktopTool(0, URL, strSavePath, 0, 0)" ascii //weight: 1
        $x_1_2 = {44 69 6d 20 77 73 68 20 41 73 20 4f 62 6a 65 63 74 0d 0a 20 20 20 20 20 20 20 20 53 65 74 20 77 73 68 20 3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 0d 0a 20 20 20 20 20 20 20 20 44 69 6d 20 77 61 69 74 4f 6e 52 65 74 75 72 6e 20 41 73 20 42 6f 6f 6c 65 61 6e 3a 20 77 61 69 74 4f 6e 52 65 74 75 72 6e 20 3d 20 54 72 75 65 0d 0a 20 20 20 20 20 20 20 20 44 69 6d 20 77 69 6e 64 6f 77 53 74 79 6c 65 20 41 73 20 49 6e 74 65 67 65 72 3a 20 77 69 6e 64 6f 77 53 74 79 6c 65 20 3d 20 31 0d 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


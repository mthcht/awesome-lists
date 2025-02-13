rule TrojanDownloader_O97M_Skebpac_A_2147708666_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Skebpac.A"
        threat_id = "2147708666"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Skebpac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(\"ADODB.Stream\")" ascii //weight: 1
        $x_1_2 = "= \"http:\" &" ascii //weight: 1
        $x_1_3 = "= Environ(\"TMP\")" ascii //weight: 1
        $x_1_4 = ".downloader URL, tmp_folder" ascii //weight: 1
        $x_1_5 = ".executer tmp_folder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Skebpac_B_2147708891_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Skebpac.B"
        threat_id = "2147708891"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Skebpac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 74 61 74 75 73 20 3d 20 [0-8] 28 45 76 61 6c 75 61 74 65 28 [0-3] 20 2d 20 [0-3] 29 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = "http:\" &" ascii //weight: 1
        $x_1_3 = "ShellExecuteA Evaluate(" ascii //weight: 1
        $x_1_4 = "= Environ(\"TEMP\") & \"\\" ascii //weight: 1
        $x_1_5 = "& \"upd.ex\" &" ascii //weight: 1
        $x_1_6 = "& \"/office.ex\" &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


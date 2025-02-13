rule TrojanDownloader_O97M_TinRat_A_2147735059_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/TinRat.A"
        threat_id = "2147735059"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TinRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 66 20 28 49 6e 53 74 72 28 31 2c 20 72 67 2c 20 22 5b 50 52 4f 54 45 43 54 45 44 20 43 4f 4e 54 45 4e 54 [0-1] 5d 22 29 20 3e 20 30 29 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {70 6f 73 20 3d 20 43 49 6e 74 28 28 52 6e 64 20 2a 20 63 6e 74 29 20 2b 20 31 29 0d 0a 20 20 20 20 20 20 20 20 20 20 20 20 6c 73 74 72 20 3d 20 6c 73 74 72 20 26 20 4d 69 64 28 74 70 6c 2c 20 70 6f 73 2c 20 31 29}  //weight: 1, accuracy: High
        $x_1_3 = "If (shd.Name = \"Sh000001\") Then" ascii //weight: 1
        $x_1_4 = "TBox.Text = \"US SEC Unlock document service" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_TinRat_B_2147735062_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/TinRat.B"
        threat_id = "2147735062"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TinRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Action.Path = \"wmic\"" ascii //weight: 1
        $x_1_2 = "Action.Arguments = \"PROCESS call create \"\"wscript.exe /b /e:jscript \" & rparam & \"\\\" & lparam & \"\"\"\"" ascii //weight: 1
        $x_1_3 = "bee_je \"auto.chk\", lPath, \"Sysupdate_805\"" ascii //weight: 1
        $x_1_4 = "If (shd.Name = \"Sh000001\") Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


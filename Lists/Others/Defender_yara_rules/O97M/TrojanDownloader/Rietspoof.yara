rule TrojanDownloader_O97M_Rietspoof_A_2147733699_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Rietspoof.A"
        threat_id = "2147733699"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Rietspoof"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 52 65 67 57 72 69 74 65 20 [0-32] 2c [0-32] 2c [0-32] 28 22 [0-32] 22 29 20 26 20 [0-32] 28 22 [0-4] 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = "ActiveWindow.View.ShowHiddenText = True" ascii //weight: 1
        $x_1_3 = "= Application.StartupPath + " ascii //weight: 1
        $x_1_4 = {3d 20 53 68 65 6c 6c 28 22 77 73 63 72 69 70 74 2e 65 78 65 20 22 22 22 20 2b 20 [0-32] 20 2b 20 22 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


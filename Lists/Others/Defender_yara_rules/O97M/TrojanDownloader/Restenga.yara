rule TrojanDownloader_O97M_Restenga_A_2147815892_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Restenga.A!dha"
        threat_id = "2147815892"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Restenga"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "appdatalocationenvironlocalappdatamicrosoftteamscurrentupdatezipdestinatioenvironlocalappdatamicrosoftteams" ascii //weight: 1
        $x_1_2 = "trueshell(\"cmd.exe/ccd%localappdata%\\microsoft\\teams\\current\\&workfolders.exe" ascii //weight: 1
        $x_1_3 = "sh.namespace(destinatio).copyheresh.namespace(location).items" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


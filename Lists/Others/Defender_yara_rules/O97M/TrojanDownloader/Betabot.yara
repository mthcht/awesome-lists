rule TrojanDownloader_O97M_Betabot_A_2147749277_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Betabot.A!MTB"
        threat_id = "2147749277"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Betabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Chr(50) + Chr(48) + Chr(48)" ascii //weight: 1
        $x_1_2 = ".Open \"get\", CleanEncryptSTR(\"lzPN://oiseye9y4owys.vw" ascii //weight: 1
        $x_1_3 = ".Status = 200 Then" ascii //weight: 1
        $x_1_4 = ".SpecialFolders(\"Templates\")" ascii //weight: 1
        $x_1_5 = "ThisASC = IntFromArray(Asc(Mid(MyString, i, 1))," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


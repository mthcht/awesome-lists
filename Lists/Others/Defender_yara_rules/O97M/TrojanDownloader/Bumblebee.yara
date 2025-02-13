rule TrojanDownloader_O97M_Bumblebee_PDA_2147834957_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bumblebee.PDA!MTB"
        threat_id = "2147834957"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".SpecialFolders(\"MyDocuments\") & \"\\name.dll\"" ascii //weight: 1
        $x_1_2 = "MsgBox \"Something went wrong!\", vbExclamation" ascii //weight: 1
        $x_1_3 = ".Open \"GET\", \"https://irs.reviews/KFOJRIOHNV(R)(A#IFK)_FIO#)_FK_D/0411r_cr4.dll\", bGetAsAsync, \"userid\", \"pass\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Bumblebee_RVA_2147902525_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Bumblebee.RVA!MTB"
        threat_id = "2147902525"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Bumblebee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "objshell\"b10=b10&\".run\"\"\"" ascii //weight: 1
        $x_1_2 = "=createobject(\"wscript.shell\").expandenvironmentstrings(\"%temp%\")tempfilename" ascii //weight: 1
        $x_1_3 = ".customdocumentproperties(\"specialprops3\").valuets.writelineb4ts.writelineb10&b1&\"\"\"\"\"\"&b2&\"\"\"\"\"\"\",0,-1\"" ascii //weight: 1
        $x_1_4 = "subdocument_close()module1.checkerendsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


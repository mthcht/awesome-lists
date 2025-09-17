rule TrojanDropper_O97M_Obfuse_D_2147729293_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.D"
        threat_id = "2147729293"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Create \"forfiles /p c:\\windows\\system32 /m notepad.exe /c C:\\Users\\user\\AppData\\" ascii //weight: 1
        $x_1_2 = "sProc = Environ(\"windir\") & \"\\\\SysWOW64\\\\rund\" + \"ll32.exe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_O97M_Obfuse_IY_2147742290_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.IY!MTB"
        threat_id = "2147742290"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& \"li\" & \"bc\" & \"url\" & \".d\" & \"ll\" & \",#52\", 0, False" ascii //weight: 1
        $x_1_2 = "n = \"pen\" & \"se1.t\" & \"xt\"" ascii //weight: 1
        $x_1_3 = "= fso1.GetSpecialFolder(2) & \"\\\" & n" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_JD_2147742314_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.JD!MTB"
        threat_id = "2147742314"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CallByName CreateObject(\"WS\" & Kerrosin & Dera & \".SHE\" & Galat), runt, VbMethod, Sope & \"SHE\" & Galat & \" WS\" & Kerrosin & Dera & sex & NaxaP" ascii //weight: 1
        $x_1_2 = "= \"JS\"" ascii //weight: 1
        $x_1_3 = "& \"\\home.text:con\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_KC_2147742636_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.KC!MTB"
        threat_id = "2147742636"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Environ(\"TEMP\") & \"\\13.xlsx\"" ascii //weight: 1
        $x_1_2 = "= TempName + \".zip\"" ascii //weight: 1
        $x_1_3 = "= Environ(\"TEMP\") '& \"\\UnzTmp\"" ascii //weight: 1
        $x_1_4 = "= Environ(\"APPDATA\")" ascii //weight: 1
        $x_1_5 = {2b 20 22 5c [0-18] 2e 64 6c 6c 22}  //weight: 1, accuracy: Low
        $x_1_6 = ".Item(\"xl\\embeddings\\oleObject1.bin\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_KM_2147742864_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.KM!MTB"
        threat_id = "2147742864"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\".jse\"" ascii //weight: 1
        $x_1_2 = "\"USER\"" ascii //weight: 1
        $x_1_3 = "\"PROFILE\"" ascii //weight: 1
        $x_1_4 = "UserForm1.TextBox1.Text" ascii //weight: 1
        $x_1_5 = "\"Shell.Application\"" ascii //weight: 1
        $x_1_6 = "= Environ(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_LA_2147742936_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.LA!MTB"
        threat_id = "2147742936"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\".jse\"" ascii //weight: 1
        $x_1_2 = "= Environ(\"USERPROFILE\") & Chr(92) &" ascii //weight: 1
        $x_1_3 = "= UserForm1.TextBox1.Value" ascii //weight: 1
        $x_1_4 = "ActiveDocument.Shapes.Count" ascii //weight: 1
        $x_1_5 = "= Null" ascii //weight: 1
        $x_1_6 = ".ShellExecute (start)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_LE_2147742973_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.LE!MTB"
        threat_id = "2147742973"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "& Chr(92) & Rnd & \".js\"" ascii //weight: 1
        $x_1_2 = {54 65 78 74 3a 3d 22 3d 20 22 20 2b 20 [0-20] 20 2b 20 22 20 5c 2a 20 43 61 72 64 54 65 78 74 22 2c 20 5f}  //weight: 1, accuracy: Low
        $x_1_3 = "\"MyDocuments\"" ascii //weight: 1
        $x_1_4 = "UserForm1.TextBox1.Value" ascii //weight: 1
        $x_1_5 = "MsgBox(\"There were \" & Trim(Str(" ascii //weight: 1
        $x_1_6 = {4f 70 65 6e 20 [0-37] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_LN_2147743067_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.LN!MTB"
        threat_id = "2147743067"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= ActiveDocument.AttachedTemplate.Path & Chr(92) & Rnd & \".js\"" ascii //weight: 1
        $x_1_2 = ".Text = PuncMark & \"   \"" ascii //weight: 1
        $x_1_3 = "UserForm1.TextBox1.Text" ascii //weight: 1
        $x_1_4 = "MsgBox \"Hi\"" ascii //weight: 1
        $x_1_5 = ".ShellExecute runFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_LX_2147743159_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.LX!MTB"
        threat_id = "2147743159"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= ActiveDocument.AttachedTemplate.Path & Chr(92) & Rnd & \".js\"" ascii //weight: 1
        $x_1_2 = "= UserForm1.TextBox1.Value" ascii //weight: 1
        $x_1_3 = "If ActiveDocument.FormFields(\"Text1\").Result = \"\" Then" ascii //weight: 1
        $x_1_4 = "CreateObject(\"Shell.Application\")" ascii //weight: 1
        $x_1_5 = ".ShellExecute endfilerun2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_LY_2147743172_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.LY!MTB"
        threat_id = "2147743172"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= ActiveDocument.AttachedTemplate.Path & Chr(92) & Rnd & \".js\"" ascii //weight: 1
        $x_1_2 = "MsgBox \"Hi\"" ascii //weight: 1
        $x_1_3 = "= UserForm2.TextBox3.Value" ascii //weight: 1
        $x_1_4 = ".Write get_TEXT_DATA" ascii //weight: 1
        $x_1_5 = ".ShellExecute startWarFileRun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_AK_2147743205_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.AK!MSR"
        threat_id = "2147743205"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 55 73 65 72 46 6f 72 6d 32 2e 54 65 78 74 42 6f 78 32 2e 54 61 67 20 2b 20 22 5c 7b [0-36] 7d 32 2e 64 6c 6c 22}  //weight: 1, accuracy: Low
        $x_1_2 = "(\"Shell.Application\")" ascii //weight: 1
        $x_1_3 = {6f 41 70 70 2e 4e 61 6d 65 73 70 61 63 65 28 [0-16] 29 2e 43 6f 70 79 48 65 72 65 20 6f 41 70 70 2e 4e 61 6d 65 73 70 61 63 65 28 [0-16] 29 2e 69 74 65 6d 73 2e 49 74 65 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_ME_2147743213_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.ME!MTB"
        threat_id = "2147743213"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \".jse\"" ascii //weight: 1
        $x_1_2 = "= Environ(\"USERPROFILE\")" ascii //weight: 1
        $x_1_3 = "= Chr(92)" ascii //weight: 1
        $x_1_4 = "= Rnd" ascii //weight: 1
        $x_1_5 = "= UserForm1.TextBox1.Value" ascii //weight: 1
        $x_1_6 = "= Asc(Mid(sDoc," ascii //weight: 1
        $x_1_7 = "Selection.TypeText Text:=sTemp" ascii //weight: 1
        $x_1_8 = ".Write textwrite" ascii //weight: 1
        $x_1_9 = "= CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_MF_2147743226_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.MF!MTB"
        threat_id = "2147743226"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& Chr(92) & Rnd & \".js\"" ascii //weight: 1
        $x_1_2 = "jsText = UserForm1.TextBox1.Value" ascii //weight: 1
        $x_1_3 = "CreateObject(\"Shell.Application\").ShellExecute s2fule" ascii //weight: 1
        $x_1_4 = ".Text = \" ^p\"" ascii //weight: 1
        $x_1_5 = "Set Folder = FSO.GetSpecialFolder(2)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_MI_2147743240_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.MI!MTB"
        threat_id = "2147743240"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 5c [0-20] 2e 78 6c 73 78 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 54 61 67 20 2b 20 22 5c [0-69] 2e 64 6c 6c 22}  //weight: 1, accuracy: Low
        $x_1_3 = "& \"\\oleObj\" + \"ect*.bin\"," ascii //weight: 1
        $x_1_4 = ".items.Item(\"xl\\embeddings\\oleObject1.bin\")" ascii //weight: 1
        $x_1_5 = ".Tag = Environ(\"TEMP\")" ascii //weight: 1
        $x_1_6 = ".Tag = Environ(\"APPDATA\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_MJ_2147743263_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.MJ!MTB"
        threat_id = "2147743263"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "& Chr(92) & Rnd & \".js\"" ascii //weight: 1
        $x_1_2 = {54 65 78 74 3a 3d 22 3d 20 22 20 2b 20 [0-22] 20 2b 20 22 20 5c 2a 20 43 61 72 64 54 65 78 74 22 2c 20 5f}  //weight: 1, accuracy: Low
        $x_1_3 = "jsText4Text = UserForm1.TextBox1.Text" ascii //weight: 1
        $x_1_4 = "Selection.TypeText Text:" ascii //weight: 1
        $x_1_5 = {4f 70 65 6e 20 [0-36] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_6 = "WshScript.ShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_ML_2147743272_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.ML!MTB"
        threat_id = "2147743272"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 5c [0-20] 2e 78 6c 73 78 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 54 61 67 20 2b 20 22 5c [0-69] 2e 64 6c 6c 22}  //weight: 1, accuracy: Low
        $x_1_3 = "& \"\\oleObj\" + \"ect*.bin\"," ascii //weight: 1
        $x_1_4 = ".items.Item(\"xl\\embeddings\\oleObject1.bin\")" ascii //weight: 1
        $x_1_5 = "= TempName + \".zip\"" ascii //weight: 1
        $x_1_6 = "Temp = \"'\" & ThisWorkbook.Path &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_NB_2147743380_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.NB!MTB"
        threat_id = "2147743380"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 73 65 72 46 6f 72 6d 32 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 26 20 22 5c [0-32] 2e 78 6c 73 78 22}  //weight: 1, accuracy: Low
        $x_1_2 = "+ \".d\" + \"ll\"" ascii //weight: 1
        $x_1_3 = "\"\\UnzTmp\"" ascii //weight: 1
        $x_1_4 = "& \"\\oleObj\" + \"ect*.bin\", ZipName," ascii //weight: 1
        $x_1_5 = ".Namespace(ZipFolder).CopyHere oApp.Namespace(ZipName).items.Item(\"xl\\embeddings\\oleObject1.bin\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_NK_2147743518_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.NK!MTB"
        threat_id = "2147743518"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Print #1, ThisDocument.CheckBox1.Caption" ascii //weight: 1
        $x_1_2 = ".Tag & ThisDocument.OptionButton1.Caption" ascii //weight: 1
        $x_1_3 = "MsgBox \"Error \" &" ascii //weight: 1
        $x_1_4 = "PicArray = PicArray +" ascii //weight: 1
        $x_1_5 = "Q = Q +" ascii //weight: 1
        $x_1_6 = "* Cos(" ascii //weight: 1
        $x_1_7 = {3d 20 45 6e 76 69 72 6f 6e 24 28 49 6e 74 32 53 74 72 28 22 [0-53] 22 29 29 20 26 20 49 6e 74 32 53 74 72 28 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_NL_2147743519_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.NL!MTB"
        threat_id = "2147743519"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Application.StartupPath & \"\\\" & \"margee\" & \":\" & Application.Version" ascii //weight: 1
        $x_1_2 = "\"The most thrue get application in test shell and some process a fear or script test it and power with execute .\"" ascii //weight: 1
        $x_1_3 = {26 20 22 20 2d 46 69 6c 65 50 61 74 68 20 22 22 77 22 20 26 20 53 70 6c 69 74 28 [0-16] 2c 20 22 20 22 29 28 31 34 29 20 26 20 22 22 22 20 2d 41 72 67 75 6d 22 20 26 20 22 65 6e 74 4c 69 73 74 20 40 28 27 2f 65 3a 4a 22}  //weight: 1, accuracy: Low
        $x_1_4 = {26 20 53 70 6c 69 74 28 [0-16] 2c 20 22 20 22 29 28 31 34 29 20 26 20 22 27 2c 27 5c 22 22 22 20 26 20 53 74 61 74 75 73 42 61 72 32 20 26 20 22 22 22 27 29 22 2c 20 45 6d 70 74 79 2c 20 45 6d 70 74 79 2c 20 30}  //weight: 1, accuracy: Low
        $x_1_5 = "MsgBox \"Failed to combine all PDFs\", vbCritical, \"Failed to Merge PDFs\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_NR_2147743582_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.NR!MTB"
        threat_id = "2147743582"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Temp = \"'\" & ThisWorkbook.Path" ascii //weight: 1
        $x_1_2 = "\".xlsx\"" ascii //weight: 1
        $x_1_3 = "+ \".d\" + \"ll\"" ascii //weight: 1
        $x_1_4 = "\".zip\"" ascii //weight: 1
        $x_1_5 = "\"\\oleObj\" + \"ect*.bin\", ZipName," ascii //weight: 1
        $x_1_6 = ".Namespace(ZipFolder).CopyHere oApp.Namespace(ZipName).items.Item(\"xl\\embeddings\\oleObject1.bin\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_NU_2147743602_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.NU!MTB"
        threat_id = "2147743602"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\".jse\"" ascii //weight: 1
        $x_1_2 = "Environ(\"USERPROFILE\")" ascii //weight: 1
        $x_1_3 = "Chr(92)" ascii //weight: 1
        $x_1_4 = "jsText4Text" ascii //weight: 1
        $x_1_5 = ".ShellExecute" ascii //weight: 1
        $x_1_6 = "= docThis." ascii //weight: 1
        $x_1_7 = ".CreateTextFile(nameOFFILESOFRSAV, True, True)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_NZ_2147743669_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.NZ!MTB"
        threat_id = "2147743669"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "+ \".d\" + \"ll\"" ascii //weight: 1
        $x_1_2 = {55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 20 ?? 20 22 5c [0-32] 22 20 2b 20 22 2e 78 6c 73 78 22}  //weight: 1, accuracy: Low
        $x_1_3 = "\".zip\"" ascii //weight: 1
        $x_1_4 = ".Namespace(ZipFolder).CopyHere oApp.Namespace(ZipName).items.Item(\"xl\\embeddings\\oleObject1.bin\")" ascii //weight: 1
        $x_1_5 = "ZipFolder" ascii //weight: 1
        $x_1_6 = "bin\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_OQ_2147744006_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.OQ!MTB"
        threat_id = "2147744006"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Rnd & \".\" & exeshion & \"se\"" ascii //weight: 1
        $x_1_2 = "& returnSlash(92) & nameOfFile(\"j\")" ascii //weight: 1
        $x_1_3 = "(\"USERPROFILE\")" ascii //weight: 1
        $x_1_4 = "Environ(" ascii //weight: 1
        $x_1_5 = ".CreateTextFile(fileFroSaveJsMacros, True, True)" ascii //weight: 1
        $x_1_6 = "= CreateObject(\"Shell.Application\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_OS_2147744024_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.OS!MTB"
        threat_id = "2147744024"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 5c [0-16] 2e 22 20 26 20 45 6d 70 74 79 20 26 20 22 6a 73 65 22 20 26 20 45 6d 70 74 79}  //weight: 1, accuracy: Low
        $x_1_2 = "= \"shell\"" ascii //weight: 1
        $x_1_3 = {56 42 41 2e 43 61 6c 6c 42 79 4e 61 6d 65 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-16] 20 26 20 22 2e 41 70 70 22 20 26 20 22 22 20 26 20 22 6c 69 63 61 22 20 26 20 45 6d 70 74 79 20 26 20 22 74 69 6f 6e 22 29 2c}  //weight: 1, accuracy: Low
        $x_1_4 = "& \"Ex\" & \"\" & \"ecute\", VbMethod, \"p\" & Empty & \"ower\" &" ascii //weight: 1
        $x_1_5 = {22 2d 63 6f 22 20 26 20 22 6d 6d 61 6e 64 20 22 22 47 65 74 2d [0-16] 22 20 26}  //weight: 1, accuracy: Low
        $x_1_6 = "& \"\\\"\"\"\"\", Empty, Empty," ascii //weight: 1
        $x_1_7 = "(Len(ActiveDocument.Content.Text)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_SK_2147744207_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.SK!eml"
        threat_id = "2147744207"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".ShellExecute (namerun)" ascii //weight: 1
        $x_1_2 = "= Environ(\"USERPROFILE\") & Chr(92)" ascii //weight: 1
        $x_1_3 = "= Folder & Rnd & \".jse\"" ascii //weight: 1
        $x_1_4 = "Selection.Find.Execute Replace:=wdReplaceAll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_PE_2147744218_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.PE!MTB"
        threat_id = "2147744218"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& Chr(92) & Rnd & \".js\"" ascii //weight: 1
        $x_1_2 = "Environ(\"USERPROFILE\")" ascii //weight: 1
        $x_1_3 = ".CreateTextFile(savefile, True, True)" ascii //weight: 1
        $x_1_4 = "= GetObject(\"winmgmts:\\\\.\\root\\cimv2:Win32_Process\")" ascii //weight: 1
        $x_1_5 = ".Create(runfile, Null, Null, intProcessID)" ascii //weight: 1
        $x_1_6 = "= UserForm1.TextBox1.Value" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_PH_2147744251_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.PH!MTB"
        threat_id = "2147744251"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "& \"\\value.\" & Empty & \"j\" & \"\" & \"se\"" ascii //weight: 1
        $x_1_2 = "ActiveDocument.Content.Text" ascii //weight: 1
        $x_1_3 = "\"-co\" & \"mma\" & \"\" & \"nd \"\"Get-Help\" &" ascii //weight: 1
        $x_1_4 = {56 42 41 2e 43 61 6c 6c 42 79 4e 61 6d 65 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-18] 20 26 20 22 2e 22 20 26 20 22 22 20 26 20 22 41 70 70 22 20 26 20 22 22 20 26 20 22 6c 69 63 61 22 20 26 20 22 22 20 26 20 22 74 69 6f 6e 22 29 2c 20 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_PT_2147744453_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.PT!MTB"
        threat_id = "2147744453"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 2f [0-5] 2e 6a 73 22}  //weight: 1, accuracy: Low
        $x_1_2 = "= GetObject(\"winmgmts:\\\\.\\root\\cimv2:Win32_Process\")" ascii //weight: 1
        $x_1_3 = "(Temp, \"\\\")" ascii //weight: 1
        $x_1_4 = "ActiveDocument.SaveAs FileName:=\"test_\" & DocNum & \".doc\"" ascii //weight: 1
        $x_1_5 = {2e 43 72 65 61 74 65 28 [0-48] 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 69 6e 74 50 72 6f 63 65 73 73 49 44 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_QS_2147744855_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.QS!MTB"
        threat_id = "2147744855"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Environ(str.Item(1)) & Chr(92) & Rnd & \".jse\"" ascii //weight: 1
        $x_1_2 = "UserForm1.Text.Caption" ascii //weight: 1
        $x_1_3 = "= OSF.CreateTextFile(this_is_you, True, True)" ascii //weight: 1
        $x_1_4 = ".ShellExecute this_is_you, \"\", \"C\" & \":\\\", \"open\", 1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_QT_2147744957_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.QT!MTB"
        threat_id = "2147744957"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Q = Q + 0.00034894275 * CInt(4.62610241759 + 12566.1516999828 * T)" ascii //weight: 1
        $x_1_2 = {53 65 74 20 42 65 6f 6d 65 74 72 69 63 6b 31 20 3d 20 42 65 6f 6d 65 74 72 69 63 6b 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 63 3a 5c 52 65 73 6f 75 72 63 65 73 5c [0-24] 2e 63 6d 64 22 2c 20 54 72 75 65 29}  //weight: 1, accuracy: Low
        $x_1_3 = "myUserForm1.Phone.Caption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_A_2147745033_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.A!MSR"
        threat_id = "2147745033"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".WriteLine (\"regsvr32 -s c:\\Resources\\REDclif.dll\")" ascii //weight: 1
        $x_1_2 = {3d 20 50 61 72 61 6d 53 65 74 74 69 6e 67 31 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 63 3a 5c 52 65 73 6f 75 72 63 65 73 5c [0-32] 2e 63 6d 64 22 2c 20 54 72 75 65 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 57 72 69 74 65 4c 69 6e 65 20 28 22 [0-48] 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 28 30 26 2c 20 22 63 3a 5c 52 65 73 6f 75 72 63 65 73 5c [0-32] 2e 63 6d 64 22 2c 20 30 26 2c 20 30 26 2c 20 31 26 2c 20 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_QZ_2147745186_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.QZ!MTB"
        threat_id = "2147745186"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tempPath = Environ(\"ALLUSERSPROFILE\") & Chr(92) & Rnd & \".jse\"" ascii //weight: 1
        $x_1_2 = "Open tempPath For Output As #" ascii //weight: 1
        $x_1_3 = "objShellApp.ShellExecute tempPath" ascii //weight: 1
        $x_1_4 = "If ActiveDocument.Path = \"\" Then" ascii //weight: 1
        $x_1_5 = "Call FileSaveAs" ascii //weight: 1
        $x_1_6 = {50 72 69 6e 74 20 23 ?? 2c 20 [0-8] 2e 43 6d 64 2e 43 61 70 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_QU_2147745486_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.QU!MTB"
        threat_id = "2147745486"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 45 6e 76 69 72 6f 6e 24 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 [0-48] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_2 = {26 20 22 5c [0-8] 2e 74 78 74 22}  //weight: 1, accuracy: Low
        $x_1_3 = "file.writeline (TextBox1.Text)" ascii //weight: 1
        $x_1_4 = {2e 46 6f 6c 64 65 72 45 78 69 73 74 73 28 [0-21] 29 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {4f 70 65 6e 20 [0-21] 20 46 6f 72 20 49 6e 70 75 74 20 41 73 20 23}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_RF_2147745510_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.RF!MTB"
        threat_id = "2147745510"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 45 6e 76 69 72 6f 6e 28 4d 69 64 28 22 [0-22] 22 2c 20 [0-6] 29 20 26 20 4d 69 64 28 22 [0-22] 22 2c 20 [0-2] 2c 20 [0-2] 29}  //weight: 1, accuracy: Low
        $x_1_2 = "& Chr(92) & Rnd & \".jse\"" ascii //weight: 1
        $x_1_3 = ".Replacement.Text =" ascii //weight: 1
        $x_1_4 = {4f 70 65 6e 20 [0-8] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_5 = "Print #" ascii //weight: 1
        $x_1_6 = ".Text = \"([." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_C_2147747859_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.C!MSR"
        threat_id = "2147747859"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Attribute VB_Name = \"chickenprice\"" ascii //weight: 1
        $x_1_2 = {3d 20 42 65 6e 61 6a 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 63 3a 5c [0-2] 5c 6b 65 79 6c 6f 61 64 [0-16] 2e 63 6d 64 22 2c 20 54 72 75 65 29}  //weight: 1, accuracy: Low
        $x_1_3 = "start C:\\1\\WomanLove.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_RN_2147748137_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.RN!MTB"
        threat_id = "2147748137"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Environ(\"ALLUSERSPROFILE\") & \"\\\" & Rnd & \".js\"" ascii //weight: 1
        $x_1_2 = ".Create(\"wscript.exe \" & p, Null, Null, intProcessID)" ascii //weight: 1
        $x_1_3 = "Set objWMIService = GetObject(\"winmgmts:\\\\.\\root\\cimv2:Win32_Process\")" ascii //weight: 1
        $x_1_4 = "Print #1," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_KS_2147748454_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.KS!eml"
        threat_id = "2147748454"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 42 79 4e 61 6d 65 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-15] 20 26 20 [0-15] 20 26 20 00 20 26 20 22 72 69 22 20 26 20 22 22 20 26 20 22 70 22 20 26 20 00 20 26 20 22 74 2e 22 20 26 20 [0-12] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 52 65 70 6c 61 63 65 28 [0-14] 2c 20 22 2e 74 78 74 22 2c 20 22 2e 6a 22 20 26 20 [0-15] 20 26 20 22 73 65 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 6b 6c 20 26 20 [0-14] 20 26 20 22 5c 2e 22 20 26 20 22 2e 5c 2e 2e 5c 22 20 26 20 00 20 26 20 22 6d 73 63 6f 6e 66 69 67 65 72 22 20 26}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 22 22 20 26 20 [0-14] 20 26 20 45 6d 70 74 79 20 26 20 22 5c 66 64 64 2e 22 20 26 20 [0-13] 20 26 20 22 74 78 74 22 20 26}  //weight: 1, accuracy: Low
        $x_1_5 = "Application.StartupPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_2147751620_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.MT!MTB"
        threat_id = "2147751620"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateFileA(\"C:\\Jeropit\\Poteri.BAT" ascii //weight: 1
        $x_1_2 = {48 74 79 75 5c 42 69 6f 70 65 72 5c 44 65 72 69 70 16 00 43 3a 5c}  //weight: 1, accuracy: Low
        $x_1_3 = "Set docActive = ActiveDocument" ascii //weight: 1
        $x_1_4 = "docNew.Activate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_QR_2147751865_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.QR!MTB"
        threat_id = "2147751865"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 65 74 73 74 61 74 5f 72 65 70 6f 72 74 5c [0-10] 2e 63 6d 64 22 2c 00 53 74 61 72 74 50 72 6f 63 65 73 73 20 22 63 3a 5c}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 65 74 73 74 61 74 5f 72 65 70 6f 72 74 5c [0-10] 2e 78 6d 6c 22 1f 00 22 63 3a 5c}  //weight: 1, accuracy: Low
        $x_1_3 = "Documents.Add(ActiveDocument." ascii //weight: 1
        $x_1_4 = {20 3d 20 22 63 3a 5c 6e 65 74 73 74 61 74 5f 72 65 70 6f 72 74 5c [0-5] 5c 61 63 74 69 76 65 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_RS_2147752214_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.RS!MTB"
        threat_id = "2147752214"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 49 6e 74 28 [0-7] 20 2a 20 31 30 30 29}  //weight: 1, accuracy: Low
        $x_1_2 = {20 3d 20 22 5c 73 76 63 68 6f 73 74 22 20 2b 20 53 74 72 28 [0-7] 29 20 2b 20 22 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_3 = "Environ(\"USERPROFILE\") & tmpfile" ascii //weight: 1
        $x_1_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 28 ?? 2c 20 22 6f 70 65 6e 22 2c 20 66 69 6c 65 6e 61 6d 65 2c 20 22 22 2c 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 2c 20 ?? 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_AA_2147752392_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.AA!MTB"
        threat_id = "2147752392"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = {52 65 67 57 72 69 74 65 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c [0-37] 22 2c 20 22 22 22 6d 22 20 2b 20 22 73 22 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 61 22 22 22 22 68 [0-37] 3a 22 20 2b 20 22 5c 22 20 2b 20 22 5c 22 20 2b 20 22 6a 22 20 2b 20 22 2e 22 20 2b 20 22 6d 22 20 2b 20 22 70 22 20 2b 20 22 5c [0-37] 22 22 22 2c 20 22 52 45 47 5f 53 5a 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_ST_2147752430_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.ST!MTB"
        threat_id = "2147752430"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MakeSureDirectoryPathExists" ascii //weight: 1
        $x_1_2 = {20 3d 20 73 74 72 50 61 72 68 20 26 20 22 [0-10] 22 20 26 20 22 2e 6a 73 65 22}  //weight: 1, accuracy: Low
        $x_1_3 = {20 3d 20 22 63 3a 5c 52 65 77 69 5f 43 6f 6f 6c 5c [0-10] 2e 63 6d 64 22}  //weight: 1, accuracy: Low
        $x_1_4 = {20 3d 20 22 63 3a 5c 55 73 65 72 5f 46 6f 74 6f 5c [0-10] 2e 62 61 74 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_O97M_Obfuse_VW_2147752691_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.VW!MTB"
        threat_id = "2147752691"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MakeSureDirectoryPathExists" ascii //weight: 1
        $x_1_2 = "= \"c:\\InstallShield\\\"" ascii //weight: 1
        $x_1_3 = {3d 20 73 74 72 50 61 72 68 20 26 20 22 [0-10] 22 20 26 20 22 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_1_4 = "= \"c:\\Datainv\\\"" ascii //weight: 1
        $x_1_5 = {3d 20 72 65 63 6f 72 64 20 26 20 22 [0-10] 22 20 26 20 22 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_1_6 = {53 74 61 72 74 50 72 6f 63 65 73 73 20 [0-10] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDropper_O97M_Obfuse_DB_2147752860_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.DB!MTB"
        threat_id = "2147752860"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 65 74 20 [0-192] 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 54 61 62 6c 65 73 28 (30|2d|39) 29 2e 43 65 6c 6c 28 (30|2d|39) 2c 20 (30|2d|39) 29 2e 52 61 6e 67 65}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4d 69 64 28 [0-192] 2e 54 65 78 74 2c 20 (30|2d|39) 2c 20 4c 65 6e 28 00 2e 54 65 78 74 29 20 2d 20 (30|2d|39) 29}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-192] 29 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20}  //weight: 1, accuracy: Low
        $x_1_4 = ".TextRetrievalMode.IncludeHiddenText = True" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_PNK_2147752861_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.PNK!MTB"
        threat_id = "2147752861"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 52 65 70 6c 61 63 65 28 [0-15] 2c 20 22 20 ?? 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-16] 28 22 [0-37] 26 20 22 20 ?? 2e 53 68 20 ?? 65 6c 20 ?? 6c 22 29 29 2c 20 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 2e 43 61 70 74 69 6f 6e 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {26 20 22 5c 22 20 26 20 4d 65 2e 4e 61 6d 65 20 26 20 [0-16] 20 26 20 22 2e [0-16] 2e 22}  //weight: 1, accuracy: Low
        $x_1_4 = {4e 61 6d 65 20 [0-16] 20 41 73 20 [0-16] 20 26 20 [0-16] 28 22 [0-3] 6a [0-3] 73 65 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_PN_2147752862_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.PN!MTB"
        threat_id = "2147752862"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 52 65 70 6c 61 63 65 28 [0-15] 2c 20 22 20 ?? 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-16] 28 22 [0-37] 26 20 22 20 ?? 2e 53 68 20 ?? 65 6c 20 ?? 6c 22 29 29 2c 20 [0-10] 42 75 74 74 6f 6e 31 2e 43 61 70 74 69 6f 6e 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {26 20 22 5c 22 20 26 20 4d 65 2e 4e 61 6d 65 20 26 20 [0-16] 20 26 20 22 2e [0-16] 2e 22}  //weight: 1, accuracy: Low
        $x_1_4 = {22 29 20 26 20 43 68 72 28 [0-10] 20 2b 20 (30|2d|39) 29 20 26 20 [0-10] 20 26 20 43 68 72 28 00 20 2b 20 01 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_DD_2147753930_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.DD!MTB"
        threat_id = "2147753930"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub autoclose()" ascii //weight: 1
        $x_1_2 = "= \"C:\\Test\"" ascii //weight: 1
        $x_1_3 = ".Label1.Caption" ascii //weight: 1
        $x_1_4 = "Print #1" ascii //weight: 1
        $x_1_5 = {20 26 20 22 5c [0-10] 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_1_6 = {53 74 61 72 74 50 72 6f 63 65 73 73 20 22 43 3a 5c 54 65 73 74 5c [0-10] 2e 62 61 74 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_BK_2147756381_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.BK!MTB"
        threat_id = "2147756381"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell a3fR4t & \" \" & avc6Sg" ascii //weight: 1
        $x_1_2 = "= Split(asuMWR, Chr(11 + 11 + 11 + 11))" ascii //weight: 1
        $x_1_3 = "= aKfYDQ(aP5eW(ay35o(alHV07), 15))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_BK_2147756381_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.BK!MTB"
        threat_id = "2147756381"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Open \"c:\\ProgramData\\hhheader.wpf\"" ascii //weight: 1
        $x_1_2 = "UserForm1.Label1.Caption = \"c:\\ProgramData\\hhheader.wpf\"" ascii //weight: 1
        $x_1_3 = "= CreateObject(\"w\" & CommandButton2.Caption & \".\" & CommandButton3.Caption)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_BK_2147756381_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.BK!MTB"
        threat_id = "2147756381"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& \" /W hidden /C $TempDir = [Environment]::GetFolderPath('ApplicationData')" ascii //weight: 1
        $x_1_2 = "(New-Object System.Net.WebClient).DownloadFile" ascii //weight: 1
        $x_1_3 = "https://bitbucket.org/artanoGuima/onemore/downloads/payloadEmail.exe" ascii //weight: 1
        $x_1_4 = "Start-Process 'WindowsDefenderModule.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_ZQ_2147757548_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.ZQ!MTB"
        threat_id = "2147757548"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = "Environ(\"LOCALAPPDATA\") & \"\\MicrosoftBackup\"" ascii //weight: 1
        $x_1_3 = "(\"Shell.Application\").Namespace(path1)" ascii //weight: 1
        $x_1_4 = "\"\\MicrosoftBackup\" & \"\\\" & myname & \".exe\"" ascii //weight: 1
        $x_1_5 = "AppdataAddress & \"\\nc.exe\"" ascii //weight: 1
        $x_1_6 = {2e 52 75 6e 20 43 68 72 28 [0-3] 29 20 26 20 70 61 74 68 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_RQ_2147762065_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.RQ!MTB"
        threat_id = "2147762065"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Open \"C:\\ProgramData\\Blobers.vbs\"" ascii //weight: 1
        $x_1_2 = "Writing code that works on both 32-bit and 64-bit Office" ascii //weight: 1
        $x_1_3 = "CreateObject(ThisDocument.XMLSaveThroughXSLT)" ascii //weight: 1
        $x_1_4 = "Bremen.Exec ThisDocument.DefaultTargetFrame" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_RSB_2147762196_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.RSB!MTB"
        threat_id = "2147762196"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Environ(\"TMP\") & \"\\temp.exe\"" ascii //weight: 1
        $x_1_2 = "Shell(FName + \" 127.0.0.1 4444 -e C:\\Windows\\System32\\cmd.exe\", 0)" ascii //weight: 1
        $x_1_3 = "Put #fnum, , HexDecode(CStr(vv))" ascii //weight: 1
        $x_1_4 = "Chr(\"&H\" & Mid(sData, iChar, 2))" ascii //weight: 1
        $x_1_5 = "Sub Workbook_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_SO_2147762255_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.SO!MSR"
        threat_id = "2147762255"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub autoopen()" ascii //weight: 1
        $x_1_2 = "Sub autoclose()" ascii //weight: 1
        $x_1_3 = {50 75 74 20 23 [0-1] 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {4f 70 65 6e 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c [0-7] 22 20 26 20 [0-23] 2e 54 61 67 20 46 6f 72 20 42 69 6e 61 72 79 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_5 = {53 65 74 20 [0-23] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-23] 2e 43 61 70 74 69 6f 6e 29}  //weight: 1, accuracy: Low
        $x_1_6 = {45 78 65 63 20 [0-7] 2e 44 65 66 61 75 6c 74 54 61 72 67 65 74 46 72 61 6d 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDropper_O97M_Obfuse_RW_2147762511_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.RW!MTB"
        threat_id = "2147762511"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Environ(\"Temp\")" ascii //weight: 1
        $x_1_2 = "tempFolderPath & \"\\magic.vbs\"" ascii //weight: 1
        $x_1_3 = "magicPowder" ascii //weight: 1
        $x_1_4 = "magicFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_RSW_2147763368_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.RSW!MTB"
        threat_id = "2147763368"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"W\" & Me.TextBox2.Text & UserForm1.Caption)" ascii //weight: 1
        $x_1_2 = "Application.StartupPath & \"\\..\\Meeting\"" ascii //weight: 1
        $x_1_3 = "Caption & Len(Soma) & \".xmli\"" ascii //weight: 1
        $x_1_4 = "UserForm1.TextBox2.Value = \"Script.\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_RSN_2147763386_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.RSN!MTB"
        threat_id = "2147763386"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = {6f 62 6a 53 68 65 6c 6c 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 54 45 4d 50 25 22 29 20 26 20 22 5c 63 79 6d 5f [0-19] 2e 02 03 03 62 61 74 77 73 66}  //weight: 1, accuracy: Low
        $x_1_3 = "DM.createElement(\"tmp\")" ascii //weight: 1
        $x_1_4 = "writeBytes Named, decodeBase64(Based)" ascii //weight: 1
        $x_1_5 = "Sub Document_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_RSM_2147764362_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.RSM!MTB"
        threat_id = "2147764362"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(AMbYO7DL + SCI2vO9w + Ve8xTwuM + pwBmGhry + KAfHuyjA)" ascii //weight: 1
        $x_1_2 = "BnmZjACg.Run" ascii //weight: 1
        $x_1_3 = "L4hVMF (18)" ascii //weight: 1
        $x_1_4 = "While Timer - temp < sec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_OSP_2147766086_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.OSP!MTB"
        threat_id = "2147766086"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Strtd = \"W\"" ascii //weight: 1
        $x_1_2 = "Set P_Ol7 = CreateObject(Strtd & roc2.ControlTipText & \".\" & roc3.ControlTipText)" ascii //weight: 1
        $x_1_3 = "MikeCh = UserForm1.Label1.Caption & \"pin\" & \".j\" & roc4.ControlTipText" ascii //weight: 1
        $x_1_4 = "Open \"C:\\Users\\Public\\Documents\\load.txt\" For Binary Lock Read Write As #" ascii //weight: 1
        $x_1_5 = "Name UserForm1.Label1.Caption As MikeCh" ascii //weight: 1
        $x_1_6 = "Me.Label1.Caption = MikeCh" ascii //weight: 1
        $x_1_7 = "roc4.Caption = Chr(34)" ascii //weight: 1
        $x_1_8 = "MsgBox roc2.Caption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_AJT_2147766641_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.AJT!MTB"
        threat_id = "2147766641"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Set RPThg = VBA.CreateObject(XEoBj + \"\" + rMBem)" ascii //weight: 1
        $x_1_2 = "ZQlEt JKhXJ(0) + \"32 \" + JKhXJ(3), \"\"" ascii //weight: 1
        $x_1_3 = "bYvng = Split(IGmdJ, sVNWD)" ascii //weight: 1
        $x_1_4 = "cxPJx(JKhXJ(2)).exec (CnvxD)" ascii //weight: 1
        $x_1_5 = {57 69 74 68 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 73 68 61 70 65 73 28 31 29 02 00 47 41 69 7a 7a 20 3d 20 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_EW_2147767699_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.EW!MTB"
        threat_id = "2147767699"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MsgBox counter" ascii //weight: 1
        $x_1_2 = "counter = 0" ascii //weight: 1
        $x_1_3 = "buff(counter) = ActiveSheet.Cells" ascii //weight: 1
        $x_1_4 = "putFile = FreeFile" ascii //weight: 1
        $x_1_5 = "Shell (\"cmd.exe /c start cplusconsole.jpg\")" ascii //weight: 1
        $x_1_6 = "Open \"C:\\vb\\cplusconsole.jpg\" For Binary Access Write As putFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_MM_2147769225_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.MM!MTB"
        threat_id = "2147769225"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ntgs) & \"Local\\Temp\"" ascii //weight: 1
        $x_1_2 = "AttachedTemplate.Path & \"\\W0rd.dll\"" ascii //weight: 1
        $x_1_3 = "32.exe" ascii //weight: 1
        $x_1_4 = "\"\\W0rd.dll,Start\"" ascii //weight: 1
        $x_1_5 = ".ShellExecute" ascii //weight: 1
        $x_1_6 = "RootPath & \"\\ya.wav\"" ascii //weight: 1
        $x_1_7 = "sf & \"\\ya.wav\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDropper_O97M_Obfuse_BH_2147769874_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.BH!MTB"
        threat_id = "2147769874"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".ShellExecute(fa & jsd & \"ll\" & hh, yy & \"\\W\" & \"0rd.d\" & \"ll,DllUnregisterServer" ascii //weight: 1
        $x_1_2 = "ActiveDocument.AttachedTemplate.Path & \"\\W0rd.dll" ascii //weight: 1
        $x_1_3 = "Loc\" & \"al\\Te\" & \"mp\", vbDirectory" ascii //weight: 1
        $x_1_4 = "= ActiveDocument.AttachedTemplate.Path & \"\\W0rd.dll\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_BHK_2147776312_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.BHK!MTB"
        threat_id = "2147776312"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call PfRINQcr.JcgWVDNjp" ascii //weight: 1
        $x_1_2 = "= Replace(kEZlkeB, \"mxgimly\", \"\")" ascii //weight: 1
        $x_1_3 = ".Run Gravity & \"\" & kEZlkeB, 0.0001" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_BHK_2147776312_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.BHK!MTB"
        threat_id = "2147776312"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call kFfpAqHA.bHnQgxk" ascii //weight: 1
        $x_1_2 = "= Replace(IcbbEztYb, \"iugdybfsu\", \"\")" ascii //weight: 1
        $x_1_3 = ".Run Gravity & \"\" & IcbbEztYb, 0.0001" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_RVA_2147783333_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.RVA!MTB"
        threat_id = "2147783333"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fso = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_2 = "o1.Run \"C:\\windows\\Temp\\ssg.exe\"" ascii //weight: 1
        $x_1_3 = "Set o1 = CreateObject(\"Wscript.Shell\")" ascii //weight: 1
        $x_1_4 = "ai(i) = \"&H\" & asInp(i)" ascii //weight: 1
        $x_1_5 = "asInp = Split(\"4d 5a 90 0" ascii //weight: 1
        $x_1_6 = "fso.DeleteFile (sFile)" ascii //weight: 1
        $x_1_7 = "Open sFile For Binary Lock Read Write As #nFileNum" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_FG_2147783378_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.FG!MTB"
        threat_id = "2147783378"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Environ(\"USERPROFILE\") + \"\\Documents\\Adobe Help Center\"" ascii //weight: 1
        $x_1_2 = ".FileExists(Environ(\"USERPROFILE\") + \"\\Documents\\\" + \"Eua58Y2F.txt\"" ascii //weight: 1
        $x_1_3 = "HelpCenterUpdater.vbs\"" ascii //weight: 1
        $x_1_4 = ".Run(\"wscript.exe //b \" + Chr(34) + qs + Chr(34), 4, False)" ascii //weight: 1
        $x_1_5 = "Split(str, \"\"rm\"\", -1, 0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_PRDF_2147793454_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.PRDF!MTB"
        threat_id = "2147793454"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Run(rljteogjxojdhqrepmhivsyorvlzk, byqssxsziomlzmmfqvtobuzgadpefexrnlz)" ascii //weight: 1
        $x_1_2 = "= Chr(bnhfg - 124)" ascii //weight: 1
        $x_1_3 = "= \"WSCript.shell\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_PRG_2147793460_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.PRG!MTB"
        threat_id = "2147793460"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Application.Run (\"Apply.Pick\")" ascii //weight: 1
        $x_1_2 = "Application.Run (\"Start.Work\")" ascii //weight: 1
        $x_1_3 = "Application.Run (\"Windows.Continue\")" ascii //weight: 1
        $x_1_4 = "Application.Run (\"SmartWork.SmartWork\")" ascii //weight: 1
        $x_1_5 = "streaksmv51 = upholdsnv51 & \".ma\" & \"in\"" ascii //weight: 1
        $x_1_6 = "Application.Run (streaksmv51)" ascii //weight: 1
        $x_1_7 = "= CreateObject(Chr$(87) & \"ord.Ap\" & \"pli\" & \"cat\" & \"ion\")" ascii //weight: 1
        $x_1_8 = "= \"C:\\Windows\\\"" ascii //weight: 1
        $x_1_9 = "dosagedv216 = dosagedv216 & Mid(sensory16stv, 22, 1)" ascii //weight: 1
        $x_1_10 = "= CreateObject(Chr$(87) & \"S\" & \"cr\" & \"ip\" & \"t.\" & \"sh\" & \"ell\")" ascii //weight: 1
        $x_1_11 = ".RegWrite guignolrgv51, newValue, \"REG_DWORD\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_PHE_2147793945_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.PHE!MTB"
        threat_id = "2147793945"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Chr(ophji - 130)" ascii //weight: 1
        $x_1_2 = "= \"WSCript.shell\"" ascii //weight: 1
        $x_1_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-20] 29}  //weight: 1, accuracy: Low
        $x_1_4 = "'hjgjg ffhg5645n /*/" ascii //weight: 1
        $x_1_5 = {64 73 66 73 73 61 66 20 3d 20 22 73 64 66 73 61 66 22 02 00 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 02 00 27 61 73 64 69 66 73 6a 64 20 61 6f 66 39 33 38 34}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 20 6c 6a 6b 6e 6d 6e 28 [0-3] 29 20 26 20 6c 6a 6b 6e 6d 6e 28 [0-3] 29 20 26 20 6c 6a 6b 6e 6d 6e 28 [0-3] 29 20 26 20 6c 6a 6b 6e 6d 6e 28 [0-3] 29 20 26 20 6c 6a 6b 6e 6d 6e 28 [0-3] 29 20 26 20 6c 6a 6b 6e 6d 6e 28 [0-3] 29 20 26 20 6c 6a 6b 6e 6d 6e 28 [0-3] 29 20 26 20 6c 6a 6b 6e 6d 6e 28 [0-3] 29 20 26 20 6c 6a 6b 6e 6d 6e 28 [0-3] 29 20 26 20 6c 6a 6b 6e 6d 6e 28 [0-3] 29 20 26}  //weight: 1, accuracy: Low
        $x_1_7 = {41 45 45 41 52 77 42 [0-2] 41 45 45 41 [0-2] 42 [0-2] 41 45 49 41 [0-2] 42 42 41 45 63 41 [0-2] 42 42 41 47 [0-2] 41 [0-2] 42 43 41 44 [0-2] 41 51 51 42 [0-2] 41 44 [0-2] 41 [0-2] 51 41 69 41 43 6b 41 4b 51 42 38 41 [0-2] 6b 41 [0-2] 51 42 [0-2] 41 41 3d 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_PHF_2147794143_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.PHF!MTB"
        threat_id = "2147794143"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Shell(StrReverse(\"sbv.nip\\ataDmargorP\\:C exe.tpircsc k/ dmc\"), Chr(48))" ascii //weight: 1
        $x_1_2 = "InStr(Dominios, sSplit(UBound(sSplit))) = 0 Then" ascii //weight: 1
        $x_1_3 = "= StrReverse(\"IZOIZIMIZI\")" ascii //weight: 1
        $x_1_4 = "= \"@\" Or Mid$(Email, Len(Email), 1) = \"@\" Or InStr(Email, \"@.\")" ascii //weight: 1
        $x_1_5 = "Print #MyFile, WW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_PLG_2147797649_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.PLG!MTB"
        threat_id = "2147797649"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABG" ascii //weight: 1
        $x_1_2 = "AGkAbABlACgAIgBoAHQAdABwADoALwAvAGMAbwBhAGMAaABjAGEAcgBtAGUAbgB3AGkAbABsAGkA" ascii //weight: 1
        $x_1_3 = "YQBtAHMALgBjAG8AbQAvADEANQBBADgANwBiAG8AbQBEAGwAWQBxAHAASAAyADAAMwA2ADcAbABq" ascii //weight: 1
        $x_1_4 = "Bkcbyhanppaqrfw.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_BKSY_2147799729_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.BKSY!MTB"
        threat_id = "2147799729"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Left(uuuuc, ntgs) & \"Local\\\" & iox & \"emp\", vbDirectory) = \"\" Then" ascii //weight: 1
        $x_1_2 = "Call Primer1(Folder & \"\\\" & f1.Name & \"\\\")" ascii //weight: 1
        $x_1_3 = "jvc = ddd & \"\\zoro.doc\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_PM_2147808411_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.PM!MTB"
        threat_id = "2147808411"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 31 30 38 2c 20 31 30 29 29 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 31 30 32 2c 20 31 34 29 2c 20 22 22 29 2e 52 75 6e 20 [0-32] 2e 54 65 78 74 42 6f 78 31 2e 54 65 78 74 20 26 20 [0-32] 2c 20 30 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 46 6f 72 6d 61 74 28 64 44 61 74 65 [0-10] 69 6e 74 44 61 79 [0-10] 2c 20 22 44 44 2e 4d 4d 2e 59 59 59 59 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {4f 70 65 6e 20 [0-48] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 02 00 49 66 20 49 73 4e 75 6d 65 72 69 63 28 76 53 69 6d 29 20 54 68 65 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_PKS_2147816383_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.PKS!MTB"
        threat_id = "2147816383"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Users\\Public\\update.js" ascii //weight: 1
        $x_1_2 = {77 69 6e 6d 67 6d 74 73 3a 27 2c 27 43 3a 5c [0-5] 50 72 6f 67 72 61 6d 44 61 74 61 5c [0-5] 64 64 6f 6e 64 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_3 = "mediafire.com/file/vwt2u87jfzpb0f4/3.htm/file" ascii //weight: 1
        $x_1_4 = {3d 20 52 65 70 6c 61 63 65 28 [0-10] 2c 20 22 [0-5] 22 2c 20 22 [0-3] 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_PDA_2147816414_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.PDA!MTB"
        threat_id = "2147816414"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MsgBox \"error! Re-install office" ascii //weight: 1
        $x_1_2 = "Get(askjdjawjkdokawod) _" ascii //weight: 1
        $x_1_3 = "GetObject(koakosdk) _" ascii //weight: 1
        $x_1_4 = "'2WjTghW','Win32_ProcessStartup','3551556ACfgms','CopyFile','1902954vylczN','Get','7dmvGMR','ShowWindow','155sBzhfb','winmgmts:'" ascii //weight: 1
        $x_1_5 = {43 3a 5c 78 35 63 50 72 6f 67 72 61 6d 44 61 74 61 5c 78 35 63 64 64 6f 6e 64 2e 63 6f 6d 5c 78 32 30 68 74 74 70 73 3a 2f 2f 77 77 77 2e 6d 65 64 69 61 66 69 72 65 2e 63 6f 6d 2f 66 69 6c 65 2f [0-32] 2f [0-2] 2e 68 74 6d 2f 66 69 6c 65}  //weight: 1, accuracy: Low
        $x_1_6 = "'push'](_0xff11fe['shift']());}catch(_0x589b6a)" ascii //weight: 1
        $x_1_7 = "Create (\"wscript C:\\Users\\Public\\update.js\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_SLA_2147944915_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.SLA!MTB"
        threat_id = "2147944915"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 45 6e 76 69 72 6f 6e 28 22 50 52 4f 47 52 41 4d 44 41 54 41 22 29 20 26 20 22 5c [0-31] 22 0d 0a 20 20 20 20 49 66 20 44 69 72 28 [0-15] 2c 20 76 62 44 69 72 65 63 74 6f 72 79 29 20 3d 20 22 22 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "Do While uikjhnmt.Value <> \"\"" ascii //weight: 1
        $x_1_3 = "Set uikjhnmt = uikjhnmt.Offset(1, 0)" ascii //weight: 1
        $x_1_4 = {53 68 65 6c 6c 20 [0-31] 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73}  //weight: 1, accuracy: Low
        $x_1_5 = {53 65 74 20 [0-15] 20 3d 20 53 68 65 65 74 73 28 22 [0-15] 22 29 2e 52 61 6e 67 65 28 22 [0-3] 22 29}  //weight: 1, accuracy: Low
        $x_1_6 = ".SaveToFile yjktbyt, 2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_SLB_2147945237_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.SLB!MTB"
        threat_id = "2147945237"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".RunOnlyIfNetworkAvailable = (Len(fff1a755ab7f7f89adf85eab4a800915) = CInt(StrReverse(Asc(Right(fff1a755ab7f7f89adf85eab4a800915, 1)) - Str(Mid(fff1a755ab7f7f89adf85eab4a800915, 14, 1)))))" ascii //weight: 1
        $x_1_2 = "= Replace(bbf1a755ab7f7f89adf95e1ad2fe4a800915((Asc(Mid(Right(fff1a755ab7f7f89adf85eab4a800915, 2), 1, 1)) - Asc(Mid(Right(fff1a755ab7f7f89adf85eab4a800915, 3), 1, 1)))" ascii //weight: 1
        $x_1_3 = "= b211ac55ab7f689adf50ad1aa4a812916 Xor &HC0000000 Xor b211ac55ab7f689adf50ad1aa4a8109168 Xor b211ac55ab7f689adf50ad1aa4a8119168:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_SI_2147948761_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.SI!MTB"
        threat_id = "2147948761"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7a 69 70 55 72 6c 20 3d 20 22 68 74 74 70 73 3a 2f 2f [0-31] 2e 73 70 61 63 65 2f 53 6f 66 74 73 43 6f 6d 70 61 6e 79 2f 64 2f [0-3] 2f [0-31] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {55 6e 7a 69 70 57 69 74 68 57 69 6e 52 41 52 20 7a 69 70 50 61 74 68 2c 20 74 61 72 67 65 74 46 6f 6c 64 65 72 2c 20 22 [0-31] 32 30 32 35}  //weight: 1, accuracy: Low
        $x_1_3 = "savePath = Environ(\"TEMP\") & \"\\\" & CreateRandomName() & \".pptx" ascii //weight: 1
        $x_1_4 = {70 70 74 55 72 6c 20 3d 20 22 68 74 74 70 73 3a 2f 2f 74 72 6d 6d 2e 73 70 61 63 65 2f 53 6f 66 74 73 43 6f 6d 70 61 6e 79 2f 64 2f [0-3] 2f [0-79] 22}  //weight: 1, accuracy: Low
        $x_1_5 = "DownloadFileWithProgress = fso.FileExists(savePath)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Obfuse_ABA_2147952409_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Obfuse.ABA!MTB"
        threat_id = "2147952409"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ini()setfso=createobject(\"scri\"&\"pting.f\"&\"ilesyst\"&\"emobject\")s32=\"syst\"dimv()asstringps=\"dfdhghrevhjvcfeklgbnv18mm7hdfgh\"" ascii //weight: 1
        $x_1_2 = "src)<5thenexitfunctiondimiaslongfori=1tovba.lenb(src)-5if(src(i)=&h4d)and(src(i+1)=&h5a)and(src(i+2)=&h90)then" ascii //weight: 1
        $x_1_3 = "dimraslongr=cp(0&,strptr(vba.strreverse(exec)),0&,0&,true,0&,byval0&,strptr(wd),tsi,tsa_pi)wfsotsa_pi.hp,17000" ascii //weight: 1
        $x_1_4 = "srwcrfldpfo&\"\\\"&pfo1fso.copyfilethisworkbook.path&\"\\\"&thisworkbook.name,tf&\"\\\"&objt0fso.copyfiletf&\"\\\"&tmpd,dfo&\"\\\"&prot&\"\\\"&dnauthisworkbook.protectps" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


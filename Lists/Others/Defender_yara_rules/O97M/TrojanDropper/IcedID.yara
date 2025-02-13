rule TrojanDropper_O97M_IcedID_DD_2147786712_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/IcedID.DD!MTB"
        threat_id = "2147786712"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bq \"c:\\programdata\\variableCompsFunc.hta\"" ascii //weight: 1
        $x_1_2 = "Replace(toCompareHtml, \"ayik\", \"\")" ascii //weight: 1
        $x_1_3 = "toBr(ActiveDocument.Range.Text)" ascii //weight: 1
        $x_1_4 = "Shell \"cm\" & compareCore & iFunc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_IcedID_DQ_2147786937_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/IcedID.DQ!MTB"
        threat_id = "2147786937"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bq \"c:\\programdata\\iCoreBr.hta\"" ascii //weight: 1
        $x_1_2 = "Replace(ActiveDocument.Range.Text, brProcVar, \"\")" ascii //weight: 1
        $x_1_3 = "compareVarI.forProc variableFuncProc" ascii //weight: 1
        $x_1_4 = "Shell \"cm\" & htmlBrCompare & variableFuncProc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_IcedID_PDI_2147807444_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/IcedID.PDI!MTB"
        threat_id = "2147807444"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 73 28 [0-32] 2c 20 [0-32] 29 02 00 43 72 65 61 74 65 4f 62 6a 65 63 74 28 74 65 78 74 31 28 22 63 61 74 65 67 6f 72 79 22 29 29 2e 65 78 65 63 20 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 65 78 70 6c 6f 72 65 72 20 22 20 2b 20 [0-32] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 73 20 22 22 2c 20 [0-32] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 74 65 78 74 31 28 22 6b 65 79 77 6f 72 64 73 22 29 29 02 00 57 69 74 68 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 02 00 2e 53 61 76 65 41 73}  //weight: 1, accuracy: Low
        $x_1_4 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 46 69 6e 64 2e 45 78 65 63 75 74 65 20 46 69 6e 64 54 65 78 74 3a 3d 22 78 38 22 2c 20 52 65 70 6c 61 63 65 57 69 74 68 3a 3d 22 22 2c 20 52 65 70 6c 61 63 65 3a 3d 32 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 02 00 46 75 6e 63 74 69 6f 6e 20 74 65 78 74 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_IcedID_PDIA_2147807765_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/IcedID.PDIA!MTB"
        threat_id = "2147807765"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 73 28 [0-32] 2c 20 [0-32] 29 02 00 47 65 74 4f 62 6a 65 63 74 28 22 22 2c 20 74 65 78 74 31 28 22 63 61 74 65 67 6f 72 79 22 29 29 2e 65 78 65 63 20 53 74 72 52 65 76 65 72 73 65 28 22 20 72 65 72 6f 6c 70 78 65 5c 73 77 6f 64 6e 69 77 5c 3a 63 22 29 20 2b 20 [0-32] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "ActiveDocument.Content.Find.Execute FindText:=\"&l\", ReplaceWith:=\"\", Replace:=2" ascii //weight: 1
        $x_1_3 = {53 74 72 52 65 76 65 72 73 65 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 74 65 78 74 31 28 22 6b 65 79 77 6f 72 64 73 22 29 29 02 00 57 69 74 68 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 02 00 2e 53 61 76 65 41 73 20 46 69 6c 65 4e 61 6d 65 3a 3d [0-32] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_IcedID_PDIB_2147807889_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/IcedID.PDIB!MTB"
        threat_id = "2147807889"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 73 28 [0-32] 2c 20 [0-32] 29 02 00 47 65 74 4f 62 6a 65 63 74 28 22 22 2c 20 74 65 78 74 31 28 22 63 61 74 65 67 6f 72 79 22 29 29 2e 65 78 65 63 20 53 74 72 52 65 76 65 72 73 65 28 22 20 72 65 72 6f 6c 70 78 65 5c 73 77 6f 64 6e 69 77 5c 3a 63 22 29 20 2b 20 [0-32] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "= .Execute(FindText:=\"%1\", ReplaceWith:=\"\", Replace:=2)" ascii //weight: 1
        $x_1_3 = {53 74 72 52 65 76 65 72 73 65 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 74 65 78 74 31 28 22 6b 65 79 77 6f 72 64 73 22 29 29 02 00 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 61 76 65 41 73 32 20 46 69 6c 65 4e 61 6d 65 3a 3d [0-32] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_IcedID_PDIC_2147808071_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/IcedID.PDIC!MTB"
        threat_id = "2147808071"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 73 28 [0-32] 29 02 00 47 65 74 4f 62 6a 65 63 74 28 22 22 2c 20 74 65 78 74 31 28 22 63 61 74 65 67 6f 72 79 22 29 29 2e 65 78 65 63 20 53 74 72 52 65 76 65 72 73 65 28 22 20 72 65 72 6f 6c 70 78 65 22 29 20 2b 20 [0-32] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 73 20 [0-32] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = "= .Find.Execute(FindText:=\"!0\", ReplaceWith:=\"\", Replace:=2)" ascii //weight: 1
        $x_1_4 = {53 74 72 52 65 76 65 72 73 65 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 74 65 78 74 31 28 22 6b 65 79 77 6f 72 64 73 22 29 29 02 00 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 61 76 65 41 73 32 20 46 69 6c 65 4e 61 6d 65 3a 3d [0-32] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_IcedID_PM_2147808374_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/IcedID.PM!MTB"
        threat_id = "2147808374"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 46 69 6e 64 2e 45 78 65 63 75 74 65 28 46 69 6e 64 54 65 78 74 3a 3d 22 [0-5] 22 2c 20 52 65 70 6c 61 63 65 57 69 74 68 3a 3d 22 22 2c 20 52 65 70 6c 61 63 65 3a 3d [0-2] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {47 65 74 4f 62 6a 65 63 74 28 22 22 2c 20 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 20 74 65 78 74 31 28 22 [0-20] 22 29 20 2b 20 22 20 22 20 2b}  //weight: 1, accuracy: Low
        $x_1_3 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 [0-20] 29 2e 56 61 6c 75 65}  //weight: 1, accuracy: Low
        $x_1_4 = "StrReverse(ThisDocument.text1(\"keywords\"))" ascii //weight: 1
        $x_1_5 = {2e 53 61 76 65 41 73 32 20 46 69 6c 65 4e 61 6d 65 3a 3d [0-20] 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_IcedID_PDID_2147809543_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/IcedID.PDID!MTB"
        threat_id = "2147809543"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 2e 63 6f 6e 74 65 6e 74 2e 66 69 6e 64 2e 65 78 65 63 75 74 65 28 22 [0-4] 22 2c 72 65 70 6c 61 63 65 77 69 74 68 3a 3d 22 22 2c 72 65 70 6c 61 63 65 3a 3d 32 29 65 6e 64 66 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 73 70 6c 69 74 28 67 65 74 73 74 72 28 22 63 6f 6d 70 61 6e 79 22 29 2c 22 2c 22 29 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 22 2b 6a 6f 69 6e 28 [0-31] 2c 22 2e 22 29 29 2e 65 78 65 63 67 65 74 73 74 72 28 22 63 61 74 65 67 6f 72 79 22 29 2b 22 22}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 74 72 69 6d 28 22 [0-31] 2e 22 26 67 65 74 73 74 72 28 22 63 6f 6d 6d 65 6e 74 73 22 29 2b 22 61 22 29 61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 2e 73 61 76 65 61 73 32 66 69 6c 65 6e 61 6d 65 3a 3d [0-31] 2c 66 69 6c 65 66 6f 72 6d 61 74 3a 3d 32 74 68 69 73 64 6f 63 75 6d 65 6e 74 2e 65 78 65 63 75 74 69 76 65 [0-31] 65 6e 64 73 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_IcedID_PKE_2147810720_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/IcedID.PKE!MTB"
        threat_id = "2147810720"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Split(ThisDocument.getS, \"|\")" ascii //weight: 1
        $x_1_2 = {63 4f 62 6a 65 63 74 28 [0-32] 28 30 29 20 2b 20 22 2e 22 20 2b 20 [0-32] 28 31 29 29 2e 65 78 65 63 20 [0-32] 28 32 29 20 2b 20 22 20 22 20 2b}  //weight: 1, accuracy: Low
        $x_1_3 = "p1.Find.Text = \"14_k\"" ascii //weight: 1
        $x_1_4 = "p1.Find.Replacement.Text = \"\"" ascii //weight: 1
        $x_1_5 = "p1.Find.Execute Replace:=wdReplaceAll" ascii //weight: 1
        $x_1_6 = {3d 20 54 72 69 6d 28 22 [0-32] 2e 68 22 20 26 20 [0-32] 28 33 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_IcedID_RPI_2147829801_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/IcedID.RPI!MTB"
        threat_id = "2147829801"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 66 6f 72 [0-31] 3d 30 74 6f [0-31] 28 [0-31] 29 2d 31 73 74 65 70 32 [0-31] 3d 00 2f 32 [0-31] 28 03 29 3d 32 35 35 2d [0-31] 28 [0-31] 26 [0-31] 28 02 2c 00 29 26 09 28 02 2c 00 2b 31 29 29 6e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_2 = {66 75 6e 63 74 69 6f 6e [0-31] 28 [0-31] 2c [0-31] 2c 6f 70 74 69 6f 6e 61 6c [0-31] 3d 66 61 6c 73 65 29 69 66 03 74 68 65 6e [0-31] 3d 6d 69 64 28 01 2c 02 2b 31 2c 31 29 65 6c 73 65 05 3d [0-31] 28 [0-31] 28 29 2c 01 2c 02 29 65 6e 64 69 66 00 3d 05 65 6e 64 66 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = "privatesubdocument_open()" ascii //weight: 1
        $x_1_4 = "Alias \"KillTimer\" (ByVal" ascii //weight: 1
        $x_1_5 = "Lib \"Winmm.dll\" Alias \"waveInOpen\" (ByVal" ascii //weight: 1
        $x_1_6 = "Lib \"user32\" Alias \"SetTimer\" (ByVal" ascii //weight: 1
        $x_1_7 = "= StrReverse(ActiveDocument.CustomDocumentProperties(strInput))" ascii //weight: 1
        $x_1_8 = {28 29 2e 72 65 6d 6f 76 65 28 [0-31] 28 22 [0-31] 22 29 29 [0-31] 28 29 2e 72 65 6d 6f 76 65 28 [0-31] 28 22 [0-31] 22 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_IcedID_API_2147830291_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/IcedID.API!MTB"
        threat_id = "2147830291"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 66 6f 72 [0-31] 3d 30 74 6f [0-31] 28 [0-31] 29 2d 31 73 74 65 70 32 [0-31] 3d 00 2f 32 [0-31] 28 03 29 3d 32 35 35 2d [0-31] 28 [0-31] 26 [0-31] 28 02 2c 00 29 26 09 28 02 2c 00 2b 31 29 29 6e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_2 = {66 75 6e 63 74 69 6f 6e [0-31] 28 [0-31] 2c [0-31] 2c 6f 70 74 69 6f 6e 61 6c [0-31] 3d 66 61 6c 73 65 29 69 66 03 74 68 65 6e [0-31] 3d 6d 69 64 28 01 2c 02 2b 31 2c 31 29 65 6c 73 65 05 3d [0-31] 28 [0-31] 28 29 2c 01 2c 02 29 65 6e 64 69 66 00 3d 05 65 6e 64 66 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = "ifwin64thentrueelsefalseendifendfunctionfunctionoptional" ascii //weight: 1
        $x_1_4 = "Lib \"user32\" Alias \"CallWindowProcA\" (ByVal" ascii //weight: 1
        $x_1_5 = {61 73 63 6d 69 64 [0-15] 6d 6f 64 6c 65 6e [0-15] 31 31 6d 6f 64 6c 65 6e [0-15] 31 [0-31] 6d 69 64 [0-31] 6e 65 78 74 [0-10] 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_IcedID_PDIJ_2147832364_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/IcedID.PDIJ!MTB"
        threat_id = "2147832364"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 63 73 74 72 28 35 36 38 39 29 29 66 6f 72 [0-47] 3d 31 74 6f 6c 65 6e 28 [0-50] 29 73 74 65 70 32 [0-47] 28 28 00 2d 31 29 2f 32 29 3d 63 64 65 63 28 [0-47] 26 6d 69 64 28 01 2c 00 2c 32 29 29 6e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_2 = "=\"thequickbrownfoxjumpsoverthelazydog.,#&:/\\1234567890[]()=-*'lpcxm-sn-tdh" ascii //weight: 1
        $x_1_3 = {3d 72 65 70 6c 61 63 65 28 72 65 70 6c 61 63 65 28 [0-47] 28 [0-47] 29 2c 00 28 22 37 30 32 34 34 36 33 32 34 33 37 31 22 29 2c [0-47] 28 38 29 29 2c 00 28 22 37 30 34 33 32 38 34 31 37 31 22 29 2c 03 28 33 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_IcedID_PDK_2147832906_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/IcedID.PDK!MTB"
        threat_id = "2147832906"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 63 61 6c 6c 62 79 6e 61 6d 65 28 61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 2c [0-10] 28 22 [0-32] 22 29 2c 76 62 67 65 74 2c}  //weight: 1, accuracy: Low
        $x_1_2 = "for=1tolen()step2((-1)/2)=cdec(&mid(,,2))next=endfunctionfunction()" ascii //weight: 1
        $x_1_3 = "fork=0tolen(s)-1shift=(asc(mid(key,(kmodlen(key))+1,1))modlen(s))+1" ascii //weight: 1
        $x_1_4 = "=mid(s,1,pos-1)&mid(s,pos+1,len(s))endfunctionsubdocument_open()dim()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_IcedID_PDL_2147836373_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/IcedID.PDL!MTB"
        threat_id = "2147836373"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ")fori=l-1to0step-2b(index)=cbyte(clng(h+(mid(s,i,2))))index=index+1next" ascii //weight: 1
        $x_1_2 = "=prep_dc(60,510,99,2)fori=1tolen(s)stephopstmp=stmp+d(cint(mid(s,i,hop)))nexti" ascii //weight: 1
        $x_1_3 = "=\"abnormaltermination\"msgboxx,vbcriticalendifendsubpublicfunctiondc(sasstring,optionalhopaslong=3)asstringdimd" ascii //weight: 1
        $x_1_4 = "(\".gitingore\")<>\"\"then'msgbox\"thisisanincompatibleversion,please,update.\",vbinformationelseiflh_modethendata=switchsides(activedocument." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_IcedID_PDM_2147838039_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/IcedID.PDM!MTB"
        threat_id = "2147838039"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dir(\".gattaka\")<>\"\"thenmsgbox\"notapplicableenvironment\",vbcritical,\"error\"elseendifendsubprivatefunction" ascii //weight: 1
        $x_1_2 = {3d 22 61 62 6e 6f 72 6d 61 6c 74 65 72 6d 69 6e 61 74 69 6f 6e 22 6d 73 67 62 6f 78 76 6e 66 66 76 6b 6c 61 70 75 64 6a 75 7a 2c 76 62 63 72 69 74 69 63 61 6c 65 6e 64 69 66 65 6e 64 73 75 62 70 75 62 6c 69 63 66 75 6e 63 74 69 6f 6e 72 72 68 7a 73 70 78 6b 70 68 76 76 79 28 [0-31] 2c 6f 70 74 69 6f 6e 61 6c 67 68 73 69 76 6b 73 66 65 75 6d 6e 7a 67 61 73 6c 6f 6e 67 3d 33 29 61 73 73 74 72 69 6e 67 64 69 6d}  //weight: 1, accuracy: Low
        $x_1_3 = "(60,510,99,2)forpudllqzagmavmy=1tolen(fdoeegskucopx)stepghsivksfeumnzgfmxstnluywhfyhfeagi=fmxstnluywhfyhfeagi+jzlnlozvokud(cint(mid(fdoeegskucopx,pudllqzagmavmy,ghsivksfeumnzg)))next" ascii //weight: 1
        $x_1_4 = ".gattaka\")<>\"\"thenmsgbox\"obsoleteenvironment,please,update\",vbinformationelseifzdhyapqsagzthenpnjbsrngsgckjayoasd=tylkftcicrjxfvkh(activedocument." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


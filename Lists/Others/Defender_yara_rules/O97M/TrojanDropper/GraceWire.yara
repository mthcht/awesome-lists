rule TrojanDropper_O97M_GraceWire_AJ_2147744000_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AJ!dha"
        threat_id = "2147744000"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 32 2e 54 61 67 20 2b 20 22 5c 6c 69 62 44 78 64 69 61 67 [0-5] 22}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateObject(\"Shell.\" + \"Application\")" ascii //weight: 1
        $x_1_3 = {6f 41 70 70 2e 4e 61 6d 65 73 70 61 63 65 28 [0-16] 29 2e 43 6f 70 79 48 65 72 65 20 6f 41 70 70 2e 4e 61 6d 65 73 70 61 63 65 28 [0-16] 29 2e 69 74 65 6d 73 2e 49 74 65 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_A_2147744141_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.A!MTB"
        threat_id = "2147744141"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "+ \".d\" + \"ll\"" ascii //weight: 1
        $x_1_2 = {55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 20 ?? 20 22 5c [0-32] 22 20 2b 20 22 2e 78 6c 73 78 22}  //weight: 1, accuracy: Low
        $x_1_3 = "KillArray ZipFolder & \"\\ole\" + \"Obj\" + \"ect*.bin\"" ascii //weight: 1
        $x_1_4 = ".Item(\"xl\\embeddings\\oleObject1" ascii //weight: 1
        $x_1_5 = ".Namespace(ZipFolder).CopyHere" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_B_2147744193_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.B!MTB"
        threat_id = "2147744193"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "+ \".d\" + \"ll\"" ascii //weight: 1
        $x_1_2 = {3d 20 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 20 ?? 20 22 5c [0-32] 22 20 2b 20 22 2e 78 6c}  //weight: 1, accuracy: Low
        $x_1_3 = "KillArray ZipFolder & \"\\ole\" + \"Obj\" + \"ect*.bin\"" ascii //weight: 1
        $x_1_4 = ".Item(\"xl\\embed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_C_2147744654_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.C!MTB"
        threat_id = "2147744654"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "+ \".d\" + \"ll\"" ascii //weight: 1
        $x_1_2 = {3d 20 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 20 ?? 20 22 5c [0-32] 22 20 2b 20 22 2e 64}  //weight: 1, accuracy: Low
        $x_1_3 = "KillArray ZipFolder & \"\\ole\" + \"Obj\" + \"ect*.bin\"" ascii //weight: 1
        $x_1_4 = ".Namespace(ZipFolder).CopyHere" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_D_2147745204_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.D!MTB"
        threat_id = "2147745204"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "+ \".d\" + \"ll\"" ascii //weight: 1
        $x_1_2 = "KillArray ZipFolder &" ascii //weight: 1
        $x_1_3 = "outfp = lO.pen(\"output.raw\", 1)" ascii //weight: 1
        $x_1_4 = {2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 29}  //weight: 1, accuracy: Low
        $x_1_5 = "& \". \" & _" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_K_2147745286_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.K!MTB"
        threat_id = "2147745286"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {23 49 66 20 56 42 41 37 [0-32] 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "KillArray" ascii //weight: 1
        $x_1_3 = "outfp = lO.pen(\"output.raw\", 1)" ascii //weight: 1
        $x_1_4 = {2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_O_2147745732_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.O!MTB"
        threat_id = "2147745732"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "KillArray" ascii //weight: 1
        $x_1_2 = "Call lW.rite(outfp," ascii //weight: 1
        $x_1_3 = "output.raw\"" ascii //weight: 1
        $x_1_4 = {50 75 62 6c 69 63 20 53 75 62 20 4b 69 6c 6c 41 72 72 61 79 28 [0-37] 28 29 20 41 73 20 56 61 72 69 61 6e 74 29 [0-16] 4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_W_2147746202_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.W!MTB"
        threat_id = "2147746202"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 2e 64 [0-6] 6c [0-9] 6c 22}  //weight: 1, accuracy: Low
        $x_1_2 = "Call lW.rite(outfp," ascii //weight: 1
        $x_1_3 = "output.raw\"" ascii //weight: 1
        $x_1_4 = {3d 20 54 65 78 74 42 6f 78 31 54 61 67 20 2b [0-20] 7a [0-6] 69 [0-6] 70 [0-6] 22}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_Y_2147748027_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.Y!MTB"
        threat_id = "2147748027"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Call lW.rite(outfp," ascii //weight: 1
        $x_1_2 = "output.raw\"" ascii //weight: 1
        $x_1_3 = {26 20 22 7a [0-20] 69 [0-20] 70 22}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 29}  //weight: 1, accuracy: Low
        $x_1_5 = "= MsgBox(\"FMOD error! (\" & result & \") \" &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AB_2147749369_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AB!MTB"
        threat_id = "2147749369"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Call lW.rite(outfp," ascii //weight: 1
        $x_1_2 = "output.raw\"" ascii //weight: 1
        $x_1_3 = {2b 20 22 2e 7a [0-20] 69 [0-20] 70 22}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 29}  //weight: 1, accuracy: Low
        $x_1_5 = "= MsgBox(\"FMOD error! (\" & result & \") \" &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AC_2147749421_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AC!MTB"
        threat_id = "2147749421"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Call lW.rite(outfp," ascii //weight: 1
        $x_1_2 = "output.raw\"" ascii //weight: 1
        $x_1_3 = "FMOD_Erro.rString(result))" ascii //weight: 1
        $x_1_4 = {2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 29}  //weight: 1, accuracy: Low
        $x_1_5 = "= MsgBox(\"FMOD error! (\" & result & \") \" &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AD_2147749491_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AD!MTB"
        threat_id = "2147749491"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Call lW.rite(outfp," ascii //weight: 1
        $x_1_2 = "output.raw\"" ascii //weight: 1
        $x_1_3 = "FMOD_Erro.rStr" ascii //weight: 1
        $x_1_4 = {2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 29}  //weight: 1, accuracy: Low
        $x_1_5 = "#If VBA7 Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AE_2147749503_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AE!MTB"
        threat_id = "2147749503"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Call lW.rite(outfp," ascii //weight: 1
        $x_1_2 = "output.raw\"" ascii //weight: 1
        $x_1_3 = "FMOD_Erro" ascii //weight: 1
        $x_1_4 = ".CopyHere objFolder.Items." ascii //weight: 1
        $x_1_5 = {2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 29}  //weight: 1, accuracy: Low
        $x_1_6 = "#If VBA7 Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AF_2147749521_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AF!MTB"
        threat_id = "2147749521"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 64 6c [0-9] 6c 22}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 20 26 20 22 5c [0-32] 22 20 2b 20 22 2e 78 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {2b 20 22 2e 22 20 2b 20 22 7a [0-9] 70 22}  //weight: 1, accuracy: Low
        $x_1_4 = "\"\\oleObject\"" ascii //weight: 1
        $x_1_5 = "ExecuteExcel4Macro" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AG_2147749523_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AG!MTB"
        threat_id = "2147749523"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Call lW.rite(outfp," ascii //weight: 1
        $x_1_2 = "output.raw\"" ascii //weight: 1
        $x_1_3 = "FMOD_Erro" ascii //weight: 1
        $x_1_4 = "#If Win64 And VBA7 Then" ascii //weight: 1
        $x_1_5 = {2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AH_2147749538_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AH!MTB"
        threat_id = "2147749538"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 20 2b 20 22 5c 63 6f 6e 74 72 61 63 74 5f 22}  //weight: 1, accuracy: Low
        $x_1_2 = "ExecuteExcel4Macro \"CALL(\"\"\" +" ascii //weight: 1
        $x_1_3 = "examples/media/wave.mp3" ascii //weight: 1
        $x_1_4 = "VBComponentExists(\"ThisWorkbook\"," ascii //weight: 1
        $x_1_5 = "ThisWorkbook.Sheets.Copy" ascii //weight: 1
        $x_1_6 = "= \"/blob\" & CStr(GetRan.domInteger()) & \":\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AI_2147749607_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AI!MTB"
        threat_id = "2147749607"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "#If VBA7 Then" ascii //weight: 1
        $x_1_2 = "Private Declare PtrSafe Function GetWindowLong _" ascii //weight: 1
        $x_1_3 = {2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 29}  //weight: 1, accuracy: Low
        $x_1_4 = "ThisWorkbook.Sheets.Copy" ascii //weight: 1
        $x_1_5 = {4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 [0-37] 43 61 6c 6c 20 49 49 74 6d 73 2e 52 65 6d 6f 76 65 28 4b 65 79 29}  //weight: 1, accuracy: Low
        $x_1_6 = "Unload M.e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AJ_2147749608_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AJ!MTB"
        threat_id = "2147749608"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#If Win64 Then" ascii //weight: 1
        $x_1_2 = "FMOD_OK Then" ascii //weight: 1
        $x_1_3 = "Debug.Print \"Error occured when try to save \" & wBook.Name" ascii //weight: 1
        $x_1_4 = "Private Declare PtrSafe Function BoxWSL _" ascii //weight: 1
        $x_1_5 = "FMOD_Sys.tem_Init" ascii //weight: 1
        $x_1_6 = "= Mid$(Command$, i, 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AK_2147749728_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AK!MTB"
        threat_id = "2147749728"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= OpenForBinaryLock & \".dl\" + \"l\"" ascii //weight: 1
        $x_1_2 = "CallByName objFolder2, \"CopyHere\", VbMethod, objFolder.Items.Item(\"xl\\e\" + \"mbed\" + \"dings\\oleObject1.b\" + \"in\")" ascii //weight: 1
        $x_1_3 = "= WhereToGo + \".\" + \"zi\" + \"p\"" ascii //weight: 1
        $x_1_4 = "Call SystemButtonSettings(Me, False)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AL_2147749763_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AL!MTB"
        threat_id = "2147749763"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Public Function SetResourceBytes(lpType As Long, lpID As Long, lpData() As Byte, lpFile As String) As Long" ascii //weight: 1
        $x_1_2 = "Set FucjiFilm = CreateObject(\"WScri\" + \"pt.Shell\")" ascii //weight: 1
        $x_1_3 = "UserForm6.TextBox3.Tag = FucjiFilm.SpecialFolders(UserForm6.TextBox3.Tag)" ascii //weight: 1
        $x_1_4 = "& BlobSN & BlobCnt & \"/\" & Mid(splittest(Ptr), PosEndScript)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CS_2147749773_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CS!MTB"
        threat_id = "2147749773"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Public Property Get CheckCar(car As Object, Drive As String)" ascii //weight: 1
        $x_1_2 = "CheckCar = car.SpecialFolders(\"\" & Drive)" ascii //weight: 1
        $x_1_3 = "Public Property Get SpecialFolders() As String" ascii //weight: 1
        $x_1_4 = "ElseIf tooolsetChunkI And Not tooolsetChunkQ Then" ascii //weight: 1
        $x_1_5 = "ChDir Dialog4.TextBox3.Tag" ascii //weight: 1
        $x_1_6 = "If tooolsetChunkI And j = Count And c <>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CS_2147749773_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CS!MTB"
        threat_id = "2147749773"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Run (\"Reset_RightClick\"): Run (NameDT & \"!LoadPopup\")" ascii //weight: 1
        $x_1_2 = "RegKeyRead(\"HKEY_CURRENT_USER\\Software\\BacNamSoft\\Dutoan\\AutoRename\") = \"1\"" ascii //weight: 1
        $x_1_3 = {3d 20 54 72 75 65 20 54 68 65 6e 20 53 68 65 65 74 73 28 22 53 65 74 74 69 6e 67 22 29 2e 52 61 6e 67 65 28 [0-5] 29 2e 56 61 6c 75 65 20 3d 20 53 68 5f 54 48 56 54 5f 42 58 2e 4e 61 6d 65}  //weight: 1, accuracy: Low
        $x_1_4 = "Set myWS = CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_5 = "RegKeyRead = myWS.RegRead(i_RegKey)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AM_2147749806_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AM!MTB"
        threat_id = "2147749806"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& \".dl\" + \"l\"" ascii //weight: 1
        $x_1_2 = "UserForm6.TextBox3.Tag + \"\\contract_\"" ascii //weight: 1
        $x_1_3 = "ThisWorkbook.Sheets.Copy" ascii //weight: 1
        $x_1_4 = "#If VBA7 Then" ascii //weight: 1
        $x_1_5 = "FMOD_Syst.em_Create(System)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AN_2147749827_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AN!MTB"
        threat_id = "2147749827"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#If VBA7 And Win64 Then" ascii //weight: 1
        $x_1_2 = "formsFolder = \"C:\\Users\\GalkinVa\\files_for_transport\"" ascii //weight: 1
        $x_1_3 = "FMOD_Er_ro.rStr.ing" ascii //weight: 1
        $x_1_4 = "= UserForm6.TextBox1.Tag &" ascii //weight: 1
        $x_1_5 = "Unload M.e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AO_2147749998_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AO!MTB"
        threat_id = "2147749998"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 2e 64 [0-6] 6c [0-9] 6c 22}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 57 68 65 72 65 54 6f 47 6f [0-18] 22 7a [0-9] 69 [0-9] 70}  //weight: 1, accuracy: Low
        $x_1_3 = "UserForm6.TextBox3.Tag" ascii //weight: 1
        $x_1_4 = ", FMOD_" ascii //weight: 1
        $x_1_5 = {4f 6e 20 45 72 72 6f 72 20 52 65 73 75 6d 65 20 4e 65 78 74 [0-16] 44 69 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AP_2147750167_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AP!MTB"
        threat_id = "2147750167"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FMOD" ascii //weight: 1
        $x_1_2 = "UserForm6.TextBox3.Tag = FucjiFilm.SpecialFolders(UserForm6.TextBox3.Tag)" ascii //weight: 1
        $x_1_3 = "UserForm6.TextBox3.Tag = Kodak.SpecialFolders(\"\" & UserForm6.TextBox3.Tag)" ascii //weight: 1
        $x_1_4 = "Unload M.e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AQ_2147750256_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AQ!MTB"
        threat_id = "2147750256"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= buildPathFor + \"\\ole\" + \"Obj\" + \"ect*" ascii //weight: 1
        $x_1_2 = "WhereToGo = UserForm6.TextBox1.Tag & \"\\property\" + \".xls" ascii //weight: 1
        $x_1_3 = "UserForm6.TextBox1.Tag & \"\\repository\" + \".xls" ascii //weight: 1
        $x_1_4 = "+ \"zi\" + \"p\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AR_2147750586_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AR!MTB"
        threat_id = "2147750586"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 64 22 [0-18] 6c [0-9] 6c [0-9] 22}  //weight: 1, accuracy: Low
        $x_1_2 = "PRP = \"%\" & UserForm6.TextBox1.Tag" ascii //weight: 1
        $x_1_3 = "= UserForm6.TextBox3.Tag + \"\\stadr_\"" ascii //weight: 1
        $x_1_4 = "Kill Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AS_2147750674_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AS!MTB"
        threat_id = "2147750674"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FMOD_OK" ascii //weight: 1
        $x_1_2 = "ofbl = ofbl &" ascii //weight: 1
        $x_1_3 = ",\"\"ladnats\"\",\"\"J\"\")" ascii //weight: 1
        $x_1_4 = ".lblSchool3(SubSlipCount) = \"X\"" ascii //weight: 1
        $x_1_5 = ".lblSchool1(i) = \"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AT_2147750750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AT!MTB"
        threat_id = "2147750750"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ms.gR.esult = MsgBox(result & \") \" & FMOD_Er_rorStr.ing(result))" ascii //weight: 1
        $x_1_2 = "FileWherePutTo2.CopyHere FileWherePutTo.Items.Item(UserForm6.Label2.Tag)" ascii //weight: 1
        $x_1_3 = "Excel.Worksheets(1).Range(Range)" ascii //weight: 1
        $x_1_4 = "= CreateObject(\"Shell.\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AU_2147750991_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AU!MTB"
        threat_id = "2147750991"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 2c 20 22 [0-8] 2e 78 6c 73 78 22 29 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 [0-16] 2c 20 22 2e 7a 69 70 22 29 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = "FileWherePutTo2.CopyHere FileWherePutTo.Items.Item(UserForm6.Label2.Tag)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AW_2147751384_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AW!MTB"
        threat_id = "2147751384"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TextBox1Tag = UserForm2.TextBox1.Tag" ascii //weight: 1
        $x_1_2 = "ZipName = TextBox1Tag + \".zip\"" ascii //weight: 1
        $x_1_3 = "Put #1, , TempZero" ascii //weight: 1
        $x_1_4 = "oApp.Namespace(ZipFolder).CopyHere objFolder.items.Item" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AX_2147751385_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AX!MTB"
        threat_id = "2147751385"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".dll\"" ascii //weight: 1
        $x_1_2 = "FMOD_" ascii //weight: 1
        $x_1_3 = "ofbl = UserForm6.TextBox3.Tag +" ascii //weight: 1
        $x_1_4 = ".SpecialFolders(\"\" & UserForm6.TextBox3.Tag" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AY_2147751433_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AY!MTB"
        threat_id = "2147751433"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Open \"output.raw\" For Random As #" ascii //weight: 1
        $x_1_2 = "outfp = lO.pen(\"output.raw\", 1)" ascii //weight: 1
        $x_1_3 = "Call lW.rite(outfp," ascii //weight: 1
        $x_1_4 = "= FMOD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_AZ_2147751742_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.AZ!MTB"
        threat_id = "2147751742"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 52 50 20 3d 20 22 25 22 20 26 20 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67}  //weight: 1, accuracy: Low
        $x_1_2 = {55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 20 3d 20 41 63 74 69 76 65 48 6f 74 62 69 74 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 50 52 50 20 2b 20 22 25 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {26 20 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 20 2b 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {55 73 65 72 46 6f 72 6d 31 2e 73 68 6f 77 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BA_2147751983_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BA!MTB"
        threat_id = "2147751983"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".dll\"" ascii //weight: 1
        $x_1_2 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 54 61 67 2c 20 22 5c [0-21] 2e 78 6c 73 78 22 29 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {55 73 65 72 46 6f 72 6d ?? 2e 54 65 78 74 42 6f 78 ?? 2e 56 61 6c 75 65 29 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = "\".zip\"), \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BB_2147752062_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BB!MTB"
        threat_id = "2147752062"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "#If VBA7 And Win64 Then" ascii //weight: 1
        $x_1_2 = {74 74 20 3d 20 74 74 20 26 20 73 54 28 69 69 29 20 26 20 22 5c 22 [0-16] 4e 65 78 74 20 69 69}  //weight: 1, accuracy: Low
        $x_1_3 = "Mi.d$(Comma.nd$, i, 1)" ascii //weight: 1
        $x_1_4 = "1 To Len(Comma.nd$)" ascii //weight: 1
        $x_1_5 = "FMOD_OK Then" ascii //weight: 1
        $x_1_6 = {55 6e 6c 6f 61 64 20 4d 2e 65 [0-16] 45 6e 64 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BC_2147756465_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BC!MTB"
        threat_id = "2147756465"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 66 62 6c 20 3d 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 2b 20 22 5c [0-16] 2e 64 6c 6c 22}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 2c 20 22 5c [0-16] 2e 78 6c 73}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 [0-16] 2c 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 56 61 6c 75 65 29 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = "ofbl = \"CALL(\"\"\" + ofbl" ascii //weight: 1
        $x_1_5 = {3d 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 [0-8] 44 69 6d 20 6f 66 62 6c 20 41 73 20 53 74 72 69 6e 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BD_2147756466_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BD!MTB"
        threat_id = "2147756466"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PRP = \"%\" & UserForm6.TextBox1.Tag" ascii //weight: 1
        $x_1_2 = "UserForm6.TextBox1.Tag = ActiveHotbit.ExpandEnvironmentStrings(PRP + \"%\")" ascii //weight: 1
        $x_1_3 = {55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 3d 20 [0-8] 2e 43 68 65 63 6b 43 61 72 28 41 63 74 69 76 65 48 6f 74 62 69 74 2c 20 22 22 20 26 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 2b 20 22 22 29 02 00 43 68 44 69 72 20 28 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 29}  //weight: 1, accuracy: Low
        $x_1_4 = ".SpecialFolders(\"\" +" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BE_2147756544_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BE!MTB"
        threat_id = "2147756544"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "If result = RCPND_FMOD_OK Then" ascii //weight: 1
        $x_1_2 = {46 6f 72 20 69 69 20 3d 20 30 20 54 6f 20 55 42 6f 75 6e 64 28 73 54 29 20 2d 20 32 [0-21] 74 74 20 3d 20 74 74 20 26 20 73 54 28 69 69 29 20 26 20 22 5c 22 [0-8] 4e 65 78 74 20 69 69}  //weight: 1, accuracy: Low
        $x_1_3 = "c = Mi.d$(Comma.nd$, i, 1)" ascii //weight: 1
        $x_1_4 = {45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 20 6f 66 62 6c 20 2b 20 22 22 22 2c 22 22 [0-7] 22 22 2c 22 22 4a 22 22 29 22}  //weight: 1, accuracy: Low
        $x_1_5 = {4b 69 6c 6c 20 4b 65 79 [0-8] 4e 65 78 74 20 4b 65 79 [0-8] 4f 6e 20 45 72 72 6f 72 20 47 6f 54 6f 20 30 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_6 = "& UserForm6.Label1.Tag, ofbl," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BF_2147756615_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BF!MTB"
        threat_id = "2147756615"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 66 62 6c 20 3d 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 2b 20 22 5c [0-16] 2e 64 6c 6c 22}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 2c 20 22 5c [0-16] 2e 78 6c 73}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 [0-16] 2c 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 56 61 6c 75 65 29 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 [0-8] 44 69 6d 20 6f 66 62 6c 20 41 73 20 53 74 72 69 6e 67}  //weight: 1, accuracy: Low
        $x_1_5 = {44 6f 45 76 65 6e 74 73 [0-21] 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 2e 43 6f 70 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BG_2147756639_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BG!MTB"
        threat_id = "2147756639"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CheckCar = car.SpecialFolders(\"\" + Drive)" ascii //weight: 1
        $x_1_2 = "PRP = \"%\" + UserForm6.TextBox1.Tag" ascii //weight: 1
        $x_1_3 = "UserForm6.TextBox3.Tag = car.CheckCar(ActiveHotbit, \"\" & UserForm6.TextBox3.Tag + \"\")" ascii //weight: 1
        $x_1_4 = "If result = RCPND_FMOD_OK Then" ascii //weight: 1
        $x_1_5 = {4b 69 6c 6c 20 4b 65 79 [0-8] 4e 65 78 74 20 4b 65 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BH_2147756759_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BH!MTB"
        threat_id = "2147756759"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 6f 6d 70 6f 73 69 74 69 6f 6e 20 [0-21] 20 26 20 55 73 65 72 46 6f 72 6d 36 2e 4c 61 62 65 6c 31 2e 54 61 67 2c 20 6f 66 62 6c 2c 20 43 75 72 72 65 6e 74 53 69 7a 65 4f 66 41 54 2c 20 73 65 6e 64 69 6e 67 73}  //weight: 1, accuracy: Low
        $x_1_2 = "FileWherePutTo2.CopyHere FileWherePutTo.Items.Item(UserForm6.Label11.Tag)" ascii //weight: 1
        $x_1_3 = "ctackPip = Join(foooBar, \"\")" ascii //weight: 1
        $x_1_4 = {44 6f 45 76 65 6e 74 73 02 00 44 65 72 54 69 70 02 00 44 6f 45 76 65 6e 74 73 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = "tt = tt & sT(ii) & \"\\\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BI_2147756804_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BI!MTB"
        threat_id = "2147756804"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 66 62 6c 20 3d 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 2b 20 22 5c [0-16] 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {63 74 61 63 6b 50 75 70 20 3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 2c 20 22 5c [0-16] 2e 78 6c 73 78 22 29 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {63 74 61 63 6b 50 6f 70 20 3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 [0-21] 2c 20 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 56 61 6c 75 65 29 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BJ_2147757346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BJ!MTB"
        threat_id = "2147757346"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CheckCar = car.SpecialFolders(\"\" + Drive)" ascii //weight: 1
        $x_1_2 = "vSpeed = Application.WorksheetFunction.Min(sp, 100)" ascii //weight: 1
        $x_1_3 = "Public Property Get SpecialFolders() As String" ascii //weight: 1
        $x_1_4 = {44 69 6d 20 74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 49 20 41 73 20 42 6f 6f 6c 65 61 6e [0-8] 44 69 6d 20 74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 51 20 41 73 20 42 6f 6f 6c 65 61 6e}  //weight: 1, accuracy: Low
        $x_1_5 = "FMOD_OK Then" ascii //weight: 1
        $x_1_6 = {45 6e 64 20 49 66 [0-4] 4e 65 78 74 20 69 [0-4] 43 6c 6f 73 65}  //weight: 1, accuracy: Low
        $x_1_7 = "ItemsVlo2.CopyHere ItemsVlo.Items.Item(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BK_2147757347_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BK!MTB"
        threat_id = "2147757347"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PRP = \"%\" + UserForm6.TextBox1.Tag" ascii //weight: 1
        $x_1_2 = "& UserForm6.Label1.Tag, ofbl," ascii //weight: 1
        $x_1_3 = {45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 20 6f 66 62 6c 20 26 20 22 22 22 2c 22 22 [0-5] 22 22 2c 22 22 4a 22 22 29 22}  //weight: 1, accuracy: Low
        $x_1_4 = {44 6f 45 76 65 6e 74 73 [0-21] 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 2e 43 6f 70 79}  //weight: 1, accuracy: Low
        $x_1_5 = "ChDir (UserForm6.TextBox1.Tag)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BL_2147757487_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BL!MTB"
        threat_id = "2147757487"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 66 62 6c 20 3d 20 [0-16] 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 2b 20 22 5c [0-16] 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {63 74 61 63 6b 50 75 70 20 3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 [0-8] 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 2c 20 22 5c [0-16] 2e 78 6c 73}  //weight: 1, accuracy: Low
        $x_1_3 = {63 74 61 63 6b 50 6f 70 20 3d 20 64 65 72 73 68 6c 65 70 20 2b 20 [0-8] 2e 54 65 78 74 42 6f 78 33 2e 56 61 6c 75 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BM_2147757562_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BM!MTB"
        threat_id = "2147757562"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ofbl = \"CA\" + \"LL(\"\"\" + ofbl" ascii //weight: 1
        $x_1_2 = "ExecuteExcel4Macro ofbl & \"\"\",\"\"rddrd\"\",\"\"J\"\")" ascii //weight: 1
        $x_1_3 = "= car.CheckCar(ActiveHotbit, \"\" & K6GOAM.TextBox3.Tag + \"\")" ascii //weight: 1
        $x_1_4 = "ChDir (K6GOAM.TextBox1.Tag)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BN_2147757631_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BN!MTB"
        threat_id = "2147757631"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 6f 72 20 69 20 3d 20 31 20 54 6f 20 4c 65 6e 28 43 6f 6d 6d 61 2e 6e 64 24 29 [0-21] 63 20 3d 20 4d 69 2e 64 24 28 43 6f 6d 6d 61 2e 6e 64 24 2c 20 69 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_2 = {50 75 62 6c 69 63 52 65 73 75 6d 45 72 61 73 65 42 79 41 72 72 61 79 4c 69 73 74 20 63 74 61 63 6b 50 6f 70 2c 20 63 74 61 63 6b 50 69 70 2c 20 6f 66 62 6c [0-16] 56 69 73 74 61 51 20 63 74 61 63 6b 50 75 70}  //weight: 1, accuracy: Low
        $x_1_3 = "ElseIf tooolsetChunkI And Not tooolsetChunkQ Then" ascii //weight: 1
        $x_1_4 = {4e 65 78 74 [0-16] 46 6f 72 20 45 61 63 68 20 4b 65 79 20 49 6e 20 70 75 74 41 72 72 61 79 42 69 67 4c 69 73 74 [0-21] 4b 69 6c 6c 20 4b 65 79 [0-16] 4e 65 78 74 20 4b 65 79 [0-8] 4f 6e 20 45 72 72 6f 72 20 47 6f 54 6f 20 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BO_2147757632_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BO!MTB"
        threat_id = "2147757632"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 72 69 76 61 74 65 20 53 75 62 20 55 73 65 72 46 6f 72 6d 5f 41 63 74 69 76 61 74 65 28 29 02 00 44 6f 45 76 65 6e 74 73}  //weight: 1, accuracy: Low
        $x_1_2 = "ctackPip = ctackPup & Page11.Range(\"A100\").Value" ascii //weight: 1
        $x_1_3 = {50 75 62 6c 69 63 52 65 73 75 6d 45 72 61 73 65 42 79 41 72 72 61 79 4c 69 73 74 20 63 74 61 63 6b 50 6f 70 2c 20 63 74 61 63 6b 50 69 70 2c 20 6f 66 62 6c [0-8] 56 69 73 74 61 51 20 63 74 61 63 6b 50 75 70}  //weight: 1, accuracy: Low
        $x_1_4 = {46 4d 4f 44 5f 4f 4b 20 54 68 65 6e [0-5] 6d 73 2e 67 52 2e 65 73 75 6c 74 20 3d 20 4d 73 67 42 6f 78 28 72 65 73 75 6c 74 20 26 20 22 29 20 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = "FileCopy ctackPup, ctackPip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BP_2147757729_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BP!MTB"
        threat_id = "2147757729"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CheckCar = car.SpecialFolders(\"\" + Drive)" ascii //weight: 1
        $x_1_2 = "vSpeed = Application.WorksheetFunction.Max(vSpeed, -100)" ascii //weight: 1
        $x_1_3 = {43 61 73 65 20 30 [0-21] 73 20 3d 20 22 4e 6f 20 68 65 61 6c 74 68 20 70 72 6f 62 6c 65 6d 73 22}  //weight: 1, accuracy: Low
        $x_1_4 = ".TextBox3.Tag = car.CheckCar(ActiveHotbit, \"\" &" ascii //weight: 1
        $x_1_5 = ".TextBox3.Tag & \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BQ_2147757730_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BQ!MTB"
        threat_id = "2147757730"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 74 61 63 6b 50 75 70 20 3d 20 4b 36 47 4f 41 4d 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 2b 20 22 5c [0-16] 2e 78 6c 73 22 20 2b 20 22 78 22}  //weight: 1, accuracy: Low
        $x_1_2 = "ctackPop = dershlep & K6GOAM.TextBox3.Value" ascii //weight: 1
        $x_1_3 = "sOfbl = ofbl + CStr(sendings) + \".dll\"" ascii //weight: 1
        $x_1_4 = "dershlep = \"\" + K6GOAM.TextBox1.Tag" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BR_2147757939_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BR!MTB"
        threat_id = "2147757939"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 64 20 49 66 [0-21] 73 4f 66 62 6c 20 3d 20 22 22 22 22 20 2b 20 73 4f 66 62 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {76 61 72 52 65 73 31 20 3d 20 45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 28 22 43 41 4c 4c 28 22 20 2b 20 73 4f 66 62 6c 20 26 20 22 22 22 2c 22 22 22 20 2b 20 22 [0-9] 22 22 2c 22 22 4a 22 22 29 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 54 65 78 74 42 6f 78 33 2e 54 61 67 29 [0-24] 73 65 6e 64 69 6e 67 73 20 3d 20 73 65 6e 64 69 6e 67 73 20 2b 20 31 [0-21] 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
        $x_1_4 = {44 69 6d 20 73 4f 66 62 6c 20 41 73 20 53 74 72 69 6e 67 [0-8] 6f 66 62 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BS_2147758136_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BS!MTB"
        threat_id = "2147758136"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PRP = \"%\" + K6GOAM.TextBox1.Tag" ascii //weight: 1
        $x_1_2 = "K6GOAM.TextBox1.Tag = ActiveHotbit.ExpandEnvironmentStrings(PRP + \"%\")" ascii //weight: 1
        $x_1_3 = "K6GOAM.TextBox3.Tag = car.CheckCar(ActiveHotbit, \"\" & K6GOAM.TextBox3.Tag & \"\")" ascii //weight: 1
        $x_1_4 = "Set car = New CarClass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BT_2147758137_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BT!MTB"
        threat_id = "2147758137"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PublicResumEraseByArrayList ctackPop, ofbl, ctackPip" ascii //weight: 1
        $x_1_2 = {49 66 20 74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 49 20 41 6e 64 20 6a 20 3d 20 43 6f 75 6e 74 20 41 6e 64 20 63 20 3c 3e 20 22 22 22 22 20 54 68 65 6e 20 47 65 74 50 2e 61 72 61 6d 20 3d 20 47 65 74 50 2e 61 72 61 6d 20 26 20 63 [0-16] 4e 65 78 74 20 69}  //weight: 1, accuracy: Low
        $x_1_3 = "c = Mi.d$(Comma.nd$, i, 1)" ascii //weight: 1
        $x_1_4 = "If result = RCPN_D_FMOD_OK Then" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BU_2147758251_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BU!MTB"
        threat_id = "2147758251"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 4f 66 62 6c 20 3d 20 6f 66 62 6c 20 2b 20 73 65 6e 64 69 6e 67 73 43 53 54 52 20 2b 20 22 2e 64 6c 6c 22 [0-5] 43 6f 6d 70 6f 73 69 74 69 6f 6e 20 64 65 72 73 68 6c 65 70 20 26 20 4b 36 47 4f 41 4d 2e 4c 61 62 65 6c 31 2e 54 61 67 2c 20 73 4f 66 62 6c 2c 20 43 75 72 72 65 6e 74 53 69 7a 65 4f 66 41 54 2c 20 73 65 6e 64 69 6e 67 73}  //weight: 1, accuracy: Low
        $x_1_2 = "DestinationKat.CopyHere harvest.Items.Item(K6GOAM.Label11.Tag)" ascii //weight: 1
        $x_1_3 = {44 6f 45 76 65 6e 74 73 02 00 44 65 72 54 69 70 02 00 44 6f 45 76 65 6e 74 73 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = "Dim ActiveHotbit As New WshShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BV_2147758252_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BV!MTB"
        threat_id = "2147758252"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "K6GOAM.Label11.Tag" ascii //weight: 1
        $x_1_2 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 53 70 65 65 64 28 29 20 41 73 20 49 6e 74 65 67 65 72 [0-8] 53 70 65 65 64 20 3d 20 76 53 70 65 65 64}  //weight: 1, accuracy: Low
        $x_1_3 = "vSpeed = Application.WorksheetFunction.Min(sp, 100)" ascii //weight: 1
        $x_1_4 = {76 53 70 65 65 64 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 57 6f 72 6b 73 68 65 65 74 46 75 6e 63 74 69 6f 6e 2e 4d 61 78 28 76 53 70 65 65 64 2c 20 2d 31 30 30 29 02 00 45 6e 64 20 50 72 6f 70 65 72 74 79}  //weight: 1, accuracy: Low
        $x_1_5 = "CheckCar = car.SpecialFolders(\"\" & Drive)" ascii //weight: 1
        $x_1_6 = {49 66 20 4c 65 6e 28 6c 70 29 20 3c 3e 20 36 20 54 68 65 6e 20 45 72 72 2e 52 61 69 73 65 20 28 78 6c 45 72 72 56 61 6c 75 65 29 20 27 52 61 69 73 65 20 65 72 72 6f 72 [0-16] 76 4c 69 63 65 6e 73 65 50 6c 61 74 65 20 3d 20 6c 70 02 00 45 6e 64 20 50 72 6f 70 65 72 74 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BW_2147758328_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BW!MTB"
        threat_id = "2147758328"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dershlep = \"\" + K6GOAM.TextBox1.Tag" ascii //weight: 1
        $x_1_2 = {63 74 61 63 6b 50 75 70 20 3d 20 4b 36 47 4f 41 4d 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 2b 20 22 5c [0-18] 2e 78 6c 73 22 20 2b 20 22 78 22}  //weight: 1, accuracy: Low
        $x_1_3 = "ctackPop = dershlep & K6GOAM.TextBox3.Value" ascii //weight: 1
        $x_1_4 = "ofbl = K6GOAM.TextBox3.Tag" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BX_2147758329_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BX!MTB"
        threat_id = "2147758329"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ctackPip = ctackPup & Page11.Range(\"A100\").Value" ascii //weight: 1
        $x_1_2 = "PublicResumEraseByArrayList ofbl + \"*\", ctackPop, ctackPip" ascii //weight: 1
        $x_1_3 = {46 69 6c 65 43 6f 70 79 20 63 74 61 63 6b 50 75 70 2c 20 63 74 61 63 6b 50 69 70 [0-24] 73 65 6e 64 69 6e 67 73 20 3d 20 31 [0-22] 44 69 6d 20 73 4e 4d 53 50 20 41 73 20 4e 65 77 20 53 68 65 6c 6c}  //weight: 1, accuracy: Low
        $x_1_4 = "DestinationKat.CopyHere harvest.Items.Item(textItem)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BY_2147758330_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BY!MTB"
        threat_id = "2147758330"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 64 20 49 66 02 00 4d 6f 64 75 6c 65 30 2e 57 75 7a 7a 79 42 75 64 20 38 30 30 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = "c = Mi.d$(Comma.nd$, i, 1)" ascii //weight: 1
        $x_1_3 = "For i = 1 To Len(Comma.nd$)" ascii //weight: 1
        $x_1_4 = "If tooolsetChunkI And j = Count And c <> \"" ascii //weight: 1
        $x_1_5 = "If result = RCPN_D_FMOD_OK Then" ascii //weight: 1
        $x_1_6 = "ms.gR.esult = MsgBox(result & \") \")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_BZ_2147758500_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.BZ!MTB"
        threat_id = "2147758500"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PRP = \"%\" + Windows.TextBox1.Tag" ascii //weight: 1
        $x_1_2 = "Windows.TextBox1.Tag = ActiveHotbit.ExpandEnvironmentStrings(PRP + \"%\")" ascii //weight: 1
        $x_1_3 = "Windows.TextBox3.Tag = car.CheckCar(ActiveHotbit, Windows.TextBox3.Tag & \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CA_2147758501_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CA!MTB"
        threat_id = "2147758501"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sOfbl = ofbl + sendingsCSTR + \".dll\"" ascii //weight: 1
        $x_1_2 = "Composition dershlep & Windows.Label1.Tag, sOfbl, CurrentSizeOfAT, sendings" ascii //weight: 1
        $x_1_3 = "textItem = Windows.Label11.Caption" ascii //weight: 1
        $x_1_4 = "Set DestinationKat = sNMSP.Namespace(dershlep)" ascii //weight: 1
        $x_1_5 = {4b 69 6c 6c 20 4b 65 79 [0-8] 4e 65 78 74 20 4b 65 79 [0-8] 4f 6e 20 45 72 72 6f 72 20 47 6f 54 6f 20 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CB_2147758589_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CB!MTB"
        threat_id = "2147758589"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 49 20 3d 20 54 72 75 65 [0-32] 74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 51 20 3d 20 46 61 6c 73 65 [0-32] 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
        $x_1_2 = "If tooolsetChunkI And j = Count And c <> \"\"\"\" Then GetP.aram = GetP.aram & c" ascii //weight: 1
        $x_1_3 = "c = Mi.d$(Comma.nd$, i, 1)" ascii //weight: 1
        $x_1_4 = "For i = 1 To Len(Comma.nd$)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CC_2147758590_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CC!MTB"
        threat_id = "2147758590"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ctackPup = Windows.TextBox1.Tag +" ascii //weight: 1
        $x_1_2 = {63 74 61 63 6b 50 75 70 20 3d 20 63 74 61 63 6b 50 75 70 20 2b 20 22 [0-8] 2e 78 6c 73 78 22}  //weight: 1, accuracy: Low
        $x_1_3 = "ctackPop = dershlep & Windows.TextBox3.Value" ascii //weight: 1
        $x_1_4 = "sOfbl = \"\"\"\" +" ascii //weight: 1
        $x_1_5 = "VistaQ ctackPup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CD_2147758591_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CD!MTB"
        threat_id = "2147758591"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "vSpeed = Application.WorksheetFunction.Min(sp, 100)" ascii //weight: 1
        $x_1_2 = "vSpeed = Application.WorksheetFunction.Max(vSpeed, -100)" ascii //weight: 1
        $x_1_3 = "CheckCar = car.SpecialFolders(\"\" & Drive)" ascii //weight: 1
        $x_1_4 = {49 66 20 4c 65 6e 28 6c 70 29 20 3c 3e 20 36 20 54 68 65 6e 20 45 72 72 2e 52 61 69 73 65 20 28 78 6c 45 72 72 56 61 6c 75 65 29 20 27 52 61 69 73 65 20 65 72 72 6f 72 [0-16] 76 4c 69 63 65 6e 73 65 50 6c 61 74 65 20 3d 20 6c 70}  //weight: 1, accuracy: Low
        $x_1_5 = {4f 70 65 6e 20 43 6f 6d 70 6f 73 69 74 69 6f 6e 32 20 46 6f 72 20 42 69 6e 61 72 79 20 41 63 63 65 73 73 20 52 65 61 64 20 41 73 20 44 69 73 70 75 74 65 43 68 61 6e 6e 65 6c 31 [0-4] 44 69 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CE_2147758667_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CE!MTB"
        threat_id = "2147758667"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "+ \".dll\"" ascii //weight: 1
        $x_1_2 = {43 61 73 65 20 32 [0-18] 73 20 3d 20 22 4d 61 6a 6f 72 20 68 65 61 6c 74 68 20 70 72 6f 62 6c 65 6d 73 22}  //weight: 1, accuracy: Low
        $x_1_3 = {4e 65 78 74 20 6b [0-4] 45 78 69 74 20 44 6f [0-4] 45 6c 73 65 [0-4] 63 75 72}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 54 65 78 74 42 6f 78 31 2e 54 61 67 [0-8] 44 69 6d}  //weight: 1, accuracy: Low
        $x_1_5 = "textItem = Windows.Label11.Caption" ascii //weight: 1
        $x_1_6 = "ChDir Windows.TextBox3.Tag" ascii //weight: 1
        $x_1_7 = "= sNMSP.Namespace(dershlep)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CF_2147758879_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CF!MTB"
        threat_id = "2147758879"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 74 61 63 6b 50 75 70 20 3d 20 44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 2b 20 22 5c [0-8] 22}  //weight: 1, accuracy: Low
        $x_1_2 = {63 74 61 63 6b 50 75 70 20 3d 20 63 74 61 63 6b 50 75 70 20 2b 20 22 [0-8] 2e 78 6c 73 78 22}  //weight: 1, accuracy: Low
        $x_1_3 = "ctackPop = dershlep & Dialog4.TextBox3.Value" ascii //weight: 1
        $x_1_4 = "ofbl = Dialog4.TextBox3.Tag" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CG_2147758880_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CG!MTB"
        threat_id = "2147758880"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ctackPip = ctackPup & Page11.Range(\"A115\").Value" ascii //weight: 1
        $x_1_2 = "PublicResumEraseByArrayList ofbl + \"*\", ctackPop, ctackPip" ascii //weight: 1
        $x_1_3 = "FileCopy ctackPup, ctackPip" ascii //weight: 1
        $x_1_4 = "DestinationKat.CopyHere harvest.Items.Item(Lrigat)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CH_2147758881_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CH!MTB"
        threat_id = "2147758881"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sOfbl = ofbl + sendingsCSTR + \".dll\"" ascii //weight: 1
        $x_1_2 = "Composition dershlep & Dialog4.Label1.Tag, sOfbl, CurrentSizeOfAT, sendings" ascii //weight: 1
        $x_1_3 = "sOfbl = \"\"\"\" + sOfbl" ascii //weight: 1
        $x_1_4 = {76 61 72 52 65 73 31 20 3d 20 45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 28 22 43 41 4c 4c 28 22 20 2b 20 73 4f 66 62 6c 20 2b 20 22 [0-16] 22 22 2c 22 22 4a 22 22 29 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CI_2147759113_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CI!MTB"
        threat_id = "2147759113"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PRP = \"%\" & Dialog4.TextBox1.Tag" ascii //weight: 1
        $x_1_2 = "Dialog4.TextBox3.Tag = car.CheckCar(redoMochup, Dialog4.TextBox3.ControlTipText & \"\")" ascii //weight: 1
        $x_1_3 = "Dialog4.TextBox1.Tag = redoMochup.ExpandEnvironmentStrings(PRP + \"%\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CJ_2147759114_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CJ!MTB"
        threat_id = "2147759114"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 64 20 49 66 02 00 4d 6f 64 75 6c 65 32 2e 57 75 7a 7a 79 42 75 64 20 33 39 30 30 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {44 65 72 54 69 70 02 00 44 6f 45 76 65 6e 74 73 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = {4b 69 6c 6c 20 4b 65 79 [0-8] 4e 65 78 74 20 4b 65 79 [0-8] 4f 6e 20 45 72 72 6f 72 20 47 6f 54 6f 20 30}  //weight: 1, accuracy: Low
        $x_1_4 = "Public Sub WuzzyBud(dImmer As Integer)" ascii //weight: 1
        $x_1_5 = "c = Mi.d$(Comma.nd$, i, 1)" ascii //weight: 1
        $x_1_6 = "Public Property Get CheckCar(car As Object, Drive As String)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CK_2147759115_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CK!MTB"
        threat_id = "2147759115"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "If tooolsetChunkI And j = Count And c <> \"\"\"\" Then GetP.aram = GetP.aram & c" ascii //weight: 1
        $x_1_2 = {74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 51 20 3d 20 46 61 6c 73 65 [0-8] 47 65 74 50 2e 61 72 61 6d 20 3d 20 22 22}  //weight: 1, accuracy: Low
        $x_1_3 = "ElseIf tooolsetChunkI And Not tooolsetChunkQ Then" ascii //weight: 1
        $x_1_4 = {46 72 65 65 46 69 6c 65 [0-4] 4f 70 65 6e 20 43 6f 6d 70 6f 73 69 74 69 6f 6e 32 20 46 6f 72 20 42 69 6e 61 72 79 20 41 63 63 65 73 73 20 52 65 61 64 20 41 73 20 50 72 6f 73 74 6f 50 6c 61 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {4e 65 78 74 20 48 53 50 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CL_2147759205_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CL!MTB"
        threat_id = "2147759205"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ofbl = Dialog4.TextBox3.ControlTipText" ascii //weight: 1
        $x_1_2 = {63 74 61 63 6b 50 75 70 20 3d 20 44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 2b 20 22 5c [0-8] 22}  //weight: 1, accuracy: Low
        $x_1_3 = {63 74 61 63 6b 50 75 70 20 3d 20 63 74 61 63 6b 50 75 70 20 2b 20 22 [0-3] 2e 78 6c 73 78 22}  //weight: 1, accuracy: Low
        $x_1_4 = "ctackPop = dershlep & Dialog4.TextBox3.Value" ascii //weight: 1
        $x_1_5 = "FileCopy ctackPup, ctackPip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CM_2147759302_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CM!MTB"
        threat_id = "2147759302"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sOfbl = ofbl + sendingsCSTR + \".dll\"" ascii //weight: 1
        $x_1_2 = "If HiddenEE4M(sOfbl) Then" ascii //weight: 1
        $x_1_3 = "sOfbl & \"\"\",\"\"\"" ascii //weight: 1
        $x_1_4 = {76 61 72 52 65 73 31 20 3d 20 45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 28 22 43 41 4c 4c 28 22 20 2b 20 73 4f 66 62 6c 20 2b 20 22 [0-16] 22 22 2c 22 22 4a 22 22 29 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CN_2147761586_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CN!MTB"
        threat_id = "2147761586"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sOfbl = ofbl + sendingsCSTR + \".dll\"" ascii //weight: 1
        $x_1_2 = "Composition dershlep + UserForm1.Label1.Tag, sOfbl, CurrentSizeOfAT, sendings" ascii //weight: 1
        $x_1_3 = "Dialog4.TextBox3.ControlTipText = Dialog4.TextBox3.Tag" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CO_2147761587_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CO!MTB"
        threat_id = "2147761587"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ofbl = ofbl + \"\\boost_thread\"" ascii //weight: 1
        $x_1_2 = {63 74 61 63 6b 50 75 70 20 3d 20 63 74 61 63 6b 50 75 70 20 2b 20 22 [0-16] 2e 78 6c 73 78 22}  //weight: 1, accuracy: Low
        $x_1_3 = {63 74 61 63 6b 50 75 70 20 3d 20 44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 2b 20 22 5c [0-16] 22}  //weight: 1, accuracy: Low
        $x_1_4 = "TextBox7.SelLength = TextBox7.TextLength" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CP_2147761588_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CP!MTB"
        threat_id = "2147761588"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CallByName DestinationKat, \"CopyHere\", VbMethod, harvest.Items.Item(Lrigat)" ascii //weight: 1
        $x_1_2 = "c = Mi.d$(Comma.nd$, i, 1)" ascii //weight: 1
        $x_1_3 = "s = car.CheckCar(redoMochup, Dialog4.TextBox3.ControlTipText & \"\")" ascii //weight: 1
        $x_1_4 = "s = \"Major health problems\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CQ_2147761669_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CQ!MTB"
        threat_id = "2147761669"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PRP = \"%\" & Dialog4.TextBox1.Tag" ascii //weight: 1
        $x_1_2 = "Public Sub WuzzyBud(dImmer As Integer)" ascii //weight: 1
        $x_1_3 = "Dialog4.TextBox1.Tag = redoMochup.ExpandEnvironmentStrings(PRP + \"%\")" ascii //weight: 1
        $x_1_4 = "s = \"No health problems\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CR_2147761670_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CR!MTB"
        threat_id = "2147761670"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ChDir (Dialog4.TextBox1.Tag)" ascii //weight: 1
        $x_1_2 = "Dim car As Repositor" ascii //weight: 1
        $x_1_3 = {76 61 72 52 65 73 31 20 3d 20 45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 28 22 43 41 4c 4c 28 22 20 2b 20 73 4f 66 62 6c 20 2b 20 22 [0-16] 22 22 2c 22 22 4a 22 22 29 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {45 6e 64 20 49 66 02 00 4d 6f 64 75 6c 65 32 2e 57 75 7a 7a 79 42 75 64 20 33 39 30 30 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CT_2147761782_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CT!MTB"
        threat_id = "2147761782"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sOfbl = ofbl + sendingsCSTR + \".dll\"" ascii //weight: 1
        $x_1_2 = "Composition dershlep + \"\" + UserForm1.Label1.Tag + \"\", sOfbl, CurrentSizeOfAT, sendings" ascii //weight: 1
        $x_1_3 = {73 20 3d 20 63 61 72 2e 43 68 65 63 6b 43 61 72 28 [0-21] 2c 20 44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 33 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 26 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CU_2147761783_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CU!MTB"
        threat_id = "2147761783"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 74 61 63 6b 50 75 70 20 3d 20 63 74 61 63 6b 50 75 70 20 2b 20 22 [0-8] 2e 78 6c 73 78 22}  //weight: 1, accuracy: Low
        $x_1_2 = {63 74 61 63 6b 50 69 70 20 3d 20 63 74 61 63 6b 50 75 70 20 26 20 50 61 67 65 31 31 2e 52 61 6e 67 65 28 22 [0-16] 22 29 2e 56 61 6c 75 65}  //weight: 1, accuracy: Low
        $x_1_3 = "PublicResumEraseByArrayList ofbl + \"*\", ctackPip, dershlep + UserForm1.Label1.Tag" ascii //weight: 1
        $x_1_4 = "Public Function HiddenEE4M(sOfbl)" ascii //weight: 1
        $x_1_5 = "HiddenEE4M = False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CV_2147761889_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CV!MTB"
        threat_id = "2147761889"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 61 72 52 65 73 31 20 3d 20 45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 28 22 43 41 4c 22 20 2b 20 22 4c 28 22 20 2b 20 73 4f 66 62 6c 20 2b 20 22 [0-16] 22 22 2c 22 22 4a 22 22 29 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = "HiddenEE4M = Not HiddenEE4M" ascii //weight: 1
        $x_1_3 = "c = Mi.d$(Comma.nd$, i, 1)" ascii //weight: 1
        $x_1_4 = "ChDir (Dialog4.TextBox1.Tag)" ascii //weight: 1
        $x_1_5 = {44 6f 45 76 65 6e 74 73 02 00 56 6f 6f 6f 6f 6f 68 65 61 64 02 00 44 6f 45 76 65 6e 74 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CW_2147762070_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CW!MTB"
        threat_id = "2147762070"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PRP = \"%\" & Dialog4.TextBox1.Tag" ascii //weight: 1
        $x_1_2 = "Dialog4.TextBox1.Tag = redoMochup.ExpandEnvironmentStrings(PRP + \"%\")" ascii //weight: 1
        $x_1_3 = "Dim car As Repositor" ascii //weight: 1
        $x_1_4 = "Dim SpecialPath As String" ascii //weight: 1
        $x_1_5 = "Public Sub WuzzyBud" ascii //weight: 1
        $x_1_6 = "s = \"Major health problems\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CX_2147762158_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CX!MTB"
        threat_id = "2147762158"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dershlep = \"\" + Dialog4.TextBox1.Tag" ascii //weight: 1
        $x_1_2 = "ofbl = Dialog4.TextBox3.Tag" ascii //weight: 1
        $x_1_3 = "CallByName DestinationKat, \"Copy\" + \"Here\", VbMethod, harvest.Items.Item(Lrigat)" ascii //weight: 1
        $x_1_4 = "ElseIf tooolsetChunkI Or Not tooolsetChunkQ Then" ascii //weight: 1
        $x_1_5 = "CheckCar = car.SpecialFolders(\"\" & Drive)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CY_2147762176_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CY!MTB"
        threat_id = "2147762176"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Public Property Get SpecialFolders() As String" ascii //weight: 1
        $x_1_2 = "CheckCar = car.SpecialFolders(\"\" & Drive)" ascii //weight: 1
        $x_1_3 = "Public Property Let Speed(sp As Integer)" ascii //weight: 1
        $x_1_4 = {50 75 62 6c 69 63 20 53 75 62 20 56 69 73 74 61 51 28 57 68 65 72 65 54 6f 47 6f 29 [0-5] 44 6f 45 76 65 6e 74 73}  //weight: 1, accuracy: Low
        $x_1_5 = "Public Sub Vooooohead()" ascii //weight: 1
        $x_1_6 = {45 6e 64 20 49 66 02 00 4d 6f 64 75 6c 65 32 2e 57 75 7a 7a 79 42 75 64 20 33 39 30 30 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_7 = "VistaQ ctackPup" ascii //weight: 1
        $x_1_8 = {4b 69 6c 6c 20 4b 65 79 [0-16] 4e 65 78 74 20 4b 65 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_CZ_2147762458_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.CZ!MTB"
        threat_id = "2147762458"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dershlep = \"\" + Dialog4.TextBox1.Tag" ascii //weight: 1
        $x_1_2 = "sOfbl = ofbl + flayString + \".dll\"" ascii //weight: 1
        $x_1_3 = "liquidOne = liquidOne + \"l.xlsx\"" ascii //weight: 1
        $x_1_4 = "Composition dershlep + \"\" + UserForm1.Label1.Tag + \"\" + \"\", sOfbl, NumBForRead, sendings" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DA_2147762459_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DA!MTB"
        threat_id = "2147762459"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ctackPip = liquidOne & Page11.Range(\"B115\").Value" ascii //weight: 1
        $x_1_2 = "PublicResumEraseByArrayList ofbl + \"*\", ctackPip, dershlep + UserForm1.Label1.Tag" ascii //weight: 1
        $x_1_3 = "CallByName DestinationKat, \"Copy\" + \"Here\", VbMethod, harvest.Items.Item(Lrigat)" ascii //weight: 1
        $x_1_4 = "CallByName DestinationKat, \"Co\" + \"py\" + \"Here\", VbMethod, harvest.Items.Item(Lrigat)" ascii //weight: 1
        $x_1_5 = "ofbl = Dialog4.TextBox3.Tag" ascii //weight: 1
        $x_1_6 = "ofbl = ofbl + \"\\srt_join" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DB_2147762460_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DB!MTB"
        threat_id = "2147762460"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 20 3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 45 78 63 65 6c 43 2c 20 22 45 78 65 63 75 74 65 45 22 20 2b 20 22 78 63 65 6c 34 4d 61 63 72 6f 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 22 43 41 4c 22 20 2b 20 22 4c 28 22 20 2b 20 73 4f 66 62 6c 20 2b 20 22 [0-16] 22 22 2c 22 22 4a 22 22 29 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = "Private Sub TextBox3_Change()" ascii //weight: 1
        $x_1_3 = "Public Function Vooooohead()" ascii //weight: 1
        $x_1_4 = {50 75 62 6c 69 63 20 53 75 62 20 56 69 73 74 61 51 28 57 68 65 72 65 54 6f 47 6f 29 [0-8] 44 6f 45 76 65 6e 74 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DC_2147762461_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DC!MTB"
        threat_id = "2147762461"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PRP = \"%\" & Dialog4.TextBox1.Tag" ascii //weight: 1
        $x_1_2 = "Set car = New Repositor" ascii //weight: 1
        $x_1_3 = {44 69 61 6c 6f 67 34 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 [0-8] 2c 20 22 45 78 70 22 20 2b 20 22 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 50 52 50 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 25 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = "ChDir (Dialog4.TextBox1.Tag + \"\")" ascii //weight: 1
        $x_1_5 = "Public Function WuzzyBud" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DD_2147762462_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DD!MTB"
        threat_id = "2147762462"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Public Property Get CheckCar(car As Variant, Drive As String)" ascii //weight: 1
        $x_1_2 = "CheckCar = car.SpecialFolders(\"\" & Drive)" ascii //weight: 1
        $x_1_3 = "Dialog4.TextBox1.Tag" ascii //weight: 1
        $x_1_4 = "Public Property Get SpecialFolders() As String" ascii //weight: 1
        $x_1_5 = "Public Property Get Speed() As Integer" ascii //weight: 1
        $x_1_6 = "tooolsetChunkI = False" ascii //weight: 1
        $x_1_7 = "tooolsetChunkI = True" ascii //weight: 1
        $x_1_8 = "If tooolsetChunkI And j = Count And c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DE_2147762581_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DE!MTB"
        threat_id = "2147762581"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 20 3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 45 78 63 65 6c 43 2c 20 22 45 78 65 63 75 22 20 2b 20 22 74 65 45 22 20 2b 20 22 78 63 65 6c 34 4d 61 63 72 6f 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 22 43 41 4c 22 20 2b 20 22 4c 28 22 20 2b 20 73 4f 66 62 6c 20 2b 20 22 [0-16] 22 22 2c 22 22 4a 22 22 29 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = "Private Sub TextBox3_Change()" ascii //weight: 1
        $x_1_3 = "Public Function Vooooohead()" ascii //weight: 1
        $x_1_4 = "Dialog4.TextBox1.Tag" ascii //weight: 1
        $x_1_5 = {50 75 62 6c 69 63 20 53 75 62 20 56 69 73 74 61 51 28 57 68 65 72 65 54 6f 47 6f 29 [0-8] 44 6f 45 76 65 6e 74 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DF_2147762602_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DF!MTB"
        threat_id = "2147762602"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set car = New Repositor" ascii //weight: 1
        $x_1_2 = "Dialog4.TextBox1.Tag = CallByName(TSPIP, \"Exp\" + \"andEnvironmentStrings\", VbMethod, PRP + \"\" + \"\" + \"%\")" ascii //weight: 1
        $x_1_3 = "s = car.CheckCar(TSPIP, Dialog4.TextBox3.ControlTipText & \"\")" ascii //weight: 1
        $x_1_4 = "Dialog4.TextBox3.Tag = s" ascii //weight: 1
        $x_1_5 = "Module2.WuzzyBud 3900" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DG_2147762775_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DG!MTB"
        threat_id = "2147762775"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 69 71 75 69 64 4f 6e 65 20 3d 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 2b 20 22 5c [0-16] 22}  //weight: 1, accuracy: Low
        $x_1_2 = "liquidOne = liquidOne + \"l.xlsx\"" ascii //weight: 1
        $x_1_3 = "sOfbl = ofbl + flayString + \".dll\"" ascii //weight: 1
        $x_1_4 = "ofbl = ofbl + \"\\srt_join\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DH_2147762847_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DH!MTB"
        threat_id = "2147762847"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Public Property Get CheckCar(car As Variant, Drive As String)" ascii //weight: 1
        $x_1_2 = "CheckCar = car.SpecialFolders(\"\" & Drive)" ascii //weight: 1
        $x_1_3 = "Public Property Get SpecialFolders() As String" ascii //weight: 1
        $x_1_4 = "Public Property Let LicensePlate(lp As String)" ascii //weight: 1
        $x_1_5 = "Public Property Get Speed() As Integer" ascii //weight: 1
        $x_1_6 = {4d 6f 64 75 6c 65 35 2e 52 65 64 42 75 74 74 6f 6e 20 32 39 31 30 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_7 = {44 6f 45 76 65 6e 74 73 02 00 56 6f 6f 6f 6f 6f 68 65 61 64 02 00 44 6f 45 76 65 6e 74 73 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DI_2147762848_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DI!MTB"
        threat_id = "2147762848"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PRP = \"%\" & Form0.TextBox1.Tag" ascii //weight: 1
        $x_1_2 = "TBT = TBT + \"\" + \"\"" ascii //weight: 1
        $x_1_3 = "TBT = TBT + \"%" ascii //weight: 1
        $x_1_4 = "s = \"Major health problems" ascii //weight: 1
        $x_1_5 = "TBT = TSPIP.ExpandEnvironmentStrings(TBT)" ascii //weight: 1
        $x_1_6 = "s = car.CheckCar(TSPIP, Form0.TextBox3.ControlTipText & \"\")" ascii //weight: 1
        $x_1_7 = "CallByName Form0.TextBox1, \"Tag\", VbLet, TBT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DJ_2147762849_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DJ!MTB"
        threat_id = "2147762849"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "For i = 1 To Len(Comma.nd$)" ascii //weight: 1
        $x_1_2 = "C = Mi.d$(Comma.nd$, i, 1)" ascii //weight: 1
        $x_1_3 = "If tooolsetChunkI And j = Count And C <> \"\"\"\" Then GetP.aram = GetP.aram & C" ascii //weight: 1
        $x_1_4 = "tmpStr = tmpStr & \"\\\" & tmp(i)" ascii //weight: 1
        $x_1_5 = "Public Function RedButton(dImmer As Double)" ascii //weight: 1
        $x_1_6 = "Public Function Vooooohead()" ascii //weight: 1
        $x_1_7 = "s = car.CheckCar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DK_2147762850_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DK!MTB"
        threat_id = "2147762850"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 20 3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 45 78 63 65 6c 43 2c 20 22 45 78 65 63 75 22 20 2b 20 22 74 65 45 22 20 2b 20 22 78 63 65 6c 34 4d 61 63 72 6f 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 22 43 41 4c 22 20 2b 20 22 4c 28 22 20 2b 20 73 4f 66 62 6c 20 2b 20 22 [0-16] 22 22 2c 22 22 4a 22 22 29 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = "ctackPip = liquidOne & Page11.Range(\"B115\").Value" ascii //weight: 1
        $x_1_3 = "UserForm1.Label11.Tag" ascii //weight: 1
        $x_1_4 = "Set harvest = sNMSP.Namespace(ctackPip)" ascii //weight: 1
        $x_1_5 = "CallByName DestinationKat, \"Co\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DL_2147762913_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DL!MTB"
        threat_id = "2147762913"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Co\" + \"py\" + \"Here\", VbMethod, harvest.Items.Item(Lrigat)" ascii //weight: 1
        $x_1_2 = "Range(\"A2\").Formula = \"$0\"" ascii //weight: 1
        $x_1_3 = "Range(\"N2\").Formula = \"0%\"" ascii //weight: 1
        $x_1_4 = "tmp = Split(rs, \";\")" ascii //weight: 1
        $x_1_5 = "Dim tooolsetChunkI As Boolean" ascii //weight: 1
        $x_1_6 = "Dim tooolsetChunkQ As Boolean" ascii //weight: 1
        $x_1_7 = "Public Function Vooooohead()" ascii //weight: 1
        $x_1_8 = "GetP.aram = \"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DM_2147762936_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DM!MTB"
        threat_id = "2147762936"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sOfbl = ofbl + flayString + \".d\" + \"ll" ascii //weight: 1
        $x_1_2 = {6c 69 71 75 69 64 4f 6e 65 20 3d 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 2b 20 22 5c [0-16] 22}  //weight: 1, accuracy: Low
        $x_1_3 = "liquidOne = liquidOne + \"l.xlsx\"" ascii //weight: 1
        $x_1_4 = "ofbl = ofbl + \"\\srt_join\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DN_2147763003_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DN!MTB"
        threat_id = "2147763003"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TBT = TBT + \"%\"" ascii //weight: 1
        $x_1_2 = "TBT = TSPIP.ExpandEnvironmentStrings(TBT)" ascii //weight: 1
        $x_1_3 = "CallByName Form0.TextBox1, \"Tag\", VbLet, TBT" ascii //weight: 1
        $x_1_4 = "s = car.CheckCar(TSPIP, Form0.TextBox3.ControlTipText & \"\")" ascii //weight: 1
        $x_1_5 = "PRP = \"%\" & Form0.TextBox1.Tag" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DO_2147763004_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DO!MTB"
        threat_id = "2147763004"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 20 3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 45 78 63 65 6c 43 2c 20 22 45 78 65 22 20 2b 20 22 63 75 74 65 45 22 20 2b 20 22 78 63 65 6c 34 4d 61 63 72 6f 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 22 43 41 4c 22 20 2b 20 22 4c 28 22 20 2b 20 73 4f 66 62 6c 20 2b 20 22 [0-16] 22 22 2c 22 22 4a 22 22 29 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = "sOfbl = \"\"\"\" + sOfbl &" ascii //weight: 1
        $x_1_3 = "dershlep = \"\" + Form0.TextBox1.Tag" ascii //weight: 1
        $x_1_4 = "= UserForm1.Label11.Tag" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DP_2147763085_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DP!MTB"
        threat_id = "2147763085"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Public Property Get CheckCar(car As Variant, Drive As String)" ascii //weight: 1
        $x_1_2 = "CheckCar = car.SpecialFolders(\"\" & Drive)" ascii //weight: 1
        $x_1_3 = "Public Property Get Speed() As Integer" ascii //weight: 1
        $x_1_4 = "Public Property Get SpecialFolders() As String" ascii //weight: 1
        $x_1_5 = "Public Property Let LicensePlate(lp As String)" ascii //weight: 1
        $x_1_6 = "Public Property Let Speed(sp As Integer)" ascii //weight: 1
        $x_1_7 = {4c 69 63 65 6e 73 65 50 6c 61 74 65 20 3d 20 76 4c 69 63 65 6e 73 65 50 6c 61 74 65 02 00 45 6e 64 20 50 72 6f 70 65 72 74 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DQ_2147763086_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DQ!MTB"
        threat_id = "2147763086"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Public Function RedButton(dImmer As Double)" ascii //weight: 1
        $x_1_2 = "s = \"N health problems" ascii //weight: 1
        $x_1_3 = "Public Function Vooooohead()" ascii //weight: 1
        $x_1_4 = "Range(\"L2\").Formula = \"$0\"" ascii //weight: 1
        $x_1_5 = {4d 6f 64 75 6c 65 35 2e 52 65 64 42 75 74 74 6f 6e 20 31 39 39 39 39 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DR_2147763244_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DR!MTB"
        threat_id = "2147763244"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "liquidOne = liquidOne + \"l.xlsx\"" ascii //weight: 1
        $x_1_2 = "ofbl = Form0.TextBox1.Tag" ascii //weight: 1
        $x_1_3 = "ofbl = ofbl + \"\\str_join\"" ascii //weight: 1
        $x_1_4 = "liquidOne = Form0.TextBox1.Tag +" ascii //weight: 1
        $x_1_5 = "Composition dershlep + \"\" + UserForm1.Label1.Tag + \"\" + \"\", sOfbl, NumBForRead" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DS_2147763302_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DS!MTB"
        threat_id = "2147763302"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PRP = \"%\" & Form0.TextBox1.Tag" ascii //weight: 1
        $x_1_2 = "TBT = TBT + \"\" + \"\"" ascii //weight: 1
        $x_1_3 = "TBT = TBT + \"%\"" ascii //weight: 1
        $x_1_4 = "TBT = TSPIP.ExpandEnvironmentStrings(TBT)" ascii //weight: 1
        $x_1_5 = "s = car.CheckCar(TSPIP, Form0.TextBox3.ControlTipText & \"\")" ascii //weight: 1
        $x_1_6 = "Form0.TextBox3.Tag = s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DT_2147763303_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DT!MTB"
        threat_id = "2147763303"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 45 76 65 6e 74 73 02 00 45 78 43 68 61 6e 67 65 4d 6f 6e 65 79 02 00 44 6f 45 76 65 6e 74 73 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 6f 64 75 6c 65 35 2e 52 65 64 42 75 74 74 6f 6e 20 31 39 39 39 39 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = "CheckCar = car.SpecialFolders(\"\" & Drive)" ascii //weight: 1
        $x_1_4 = "Public Function ExChangeMoney()" ascii //weight: 1
        $x_1_5 = "dershlep = \"\" & Form0.TextBox1.Tag" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DT_2147763303_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DT!MTB"
        threat_id = "2147763303"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 45 76 65 6e 74 73 02 00 45 78 43 68 61 6e 67 65 4d 6f 6e 65 79 02 00 44 6f 45 76 65 6e 74 73 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 6f 64 75 6c 65 35 2e 52 65 64 42 75 74 74 6f 6e 20 31 39 39 39 39 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = "CheckCar = car.SpecialFolders(\"\" & Drive)" ascii //weight: 1
        $x_1_4 = "Public Function ExChangeMoney()" ascii //weight: 1
        $x_1_5 = "dershlep = \"\" + Form0.TextBox1.Tag" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DU_2147763325_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DU!MTB"
        threat_id = "2147763325"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Public Declare Function roche Lib \"str_join1.dll\" () As Integer" ascii //weight: 1
        $x_1_2 = "liquidOne = liquidOne + \"l.xlsx" ascii //weight: 1
        $x_1_3 = "ofbl = Form0.TextBox1.Tag" ascii //weight: 1
        $x_1_4 = "ofbl = ofbl + \"\\str_join" ascii //weight: 1
        $x_1_5 = "Lrigat = UserForm1.Label11.Tag" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DV_2147763383_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DV!MTB"
        threat_id = "2147763383"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sOfbl = ofbl + Page11.Range(\"B115\").Value" ascii //weight: 1
        $x_1_2 = "PublicResumEraseByArrayList ofbl + \"*\", Form0.TextBox3.Tag + \"\\str_join*\", sOfbl, ctackPip, dershlep + UserForm1.Label1.Tag" ascii //weight: 1
        $x_1_3 = "PublicResumEraseByArrayList ofbl + \"*\", Form0.TextBox3.Tag + \"\\str_join*\", sOfbl, ctackPip, dershlep & UserForm1.Label1.Tag" ascii //weight: 1
        $x_1_4 = "ctackPip = liquidOne & Page11.Range(\"B115\").Value" ascii //weight: 1
        $x_1_5 = "Set ExcelC = ThisWorkbook.Sheets(1).Application.Sheets(1).Application" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DW_2147763384_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DW!MTB"
        threat_id = "2147763384"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Composition dershlep + \"\" + UserForm1.Label1.Tag + \"\" & \"\", sOfbl, NumBForRead" ascii //weight: 1
        $x_1_2 = "Set DestinationKat = sNMSP.Namespace(Form0.TextBox3.Tag)" ascii //weight: 1
        $x_1_3 = "Dim car As Lumene" ascii //weight: 1
        $x_1_4 = "DestinationKat.CopyHere harvest.Items.Item(Lrigat)" ascii //weight: 1
        $x_1_5 = "setDLLDirectory \"\" + Form0.TextBox3.Tag" ascii //weight: 1
        $x_1_6 = "VistaQ liquidOne" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DX_2147763385_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DX!MTB"
        threat_id = "2147763385"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 [0-8] 20 4c 69 62 20 22 73 74 72 5f 6a 6f 69 6e 32 2e 64 6c 6c 22 20 28 29 20 41 73 20 49 6e 74 65 67 65 72}  //weight: 1, accuracy: Low
        $x_1_2 = "ChDir (Form0.TextBox1.Tag + \"\")" ascii //weight: 1
        $x_1_3 = "sOfbl = \"\"\"\" + sOfbl & \"\"\",\"\"\"" ascii //weight: 1
        $x_1_4 = "Range(\"A2\").Formula = \"$0\"" ascii //weight: 1
        $x_1_5 = "Range(\"B2\").Formula = \"$0\"" ascii //weight: 1
        $x_1_6 = "Range(\"C2\").Formula = \"$0\"" ascii //weight: 1
        $x_1_7 = "Range(\"D2\").Formula = \"$0\"" ascii //weight: 1
        $x_1_8 = "Public Sub VistaQ(WhereToGo)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DY_2147763468_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DY!MTB"
        threat_id = "2147763468"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dim SpecialPath As String" ascii //weight: 1
        $x_1_2 = "Set car = New Lumene" ascii //weight: 1
        $x_1_3 = "Set TSPIP = New IWshRuntimeLibrary.WshShell" ascii //weight: 1
        $x_1_4 = "Public Function RedButton(dImmer As Double)" ascii //weight: 1
        $x_1_5 = "s = \"Minor health problems\"" ascii //weight: 1
        $x_1_6 = "C = Mi.d$(Comma.nd$, I, 1)" ascii //weight: 1
        $x_1_7 = "tooolsetChunkI = False" ascii //weight: 1
        $x_1_8 = "tooolsetChunkQ = False" ascii //weight: 1
        $x_1_9 = "GetP.aram = \"\"" ascii //weight: 1
        $x_1_10 = "dershlep + \"\" + UserForm1.Label1.Tag" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_DZ_2147763531_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.DZ!MTB"
        threat_id = "2147763531"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ofbl = Form0.TextBox1.Tag" ascii //weight: 1
        $x_1_2 = "ofbl = ofbl + \"\\str_join\"" ascii //weight: 1
        $x_1_3 = "liquidOne = Form0.TextBox1.Tag + \"\\academ\"" ascii //weight: 1
        $x_1_4 = "liquidOne = liquidOne + \"l.xlsx\"" ascii //weight: 1
        $x_1_5 = "Public Declare Function gdemn Lib \"str_join1.dll\" () As Integer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_EA_2147763625_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.EA!MTB"
        threat_id = "2147763625"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Set DestinationKat = sNMSP.Namespace(Form0.TextBox3.Tag)" ascii //weight: 1
        $x_1_2 = "Set harvest = sNMSP.Namespace(sOfbl)" ascii //weight: 1
        $x_1_3 = "Call ArrayInsert(b, 1, fso)" ascii //weight: 1
        $x_1_4 = "DestinationKat.CopyHere harvest.Items.Item(Lrigat)" ascii //weight: 1
        $x_1_5 = "Public Property Get Speed() As Integer" ascii //weight: 1
        $x_1_6 = "Public Sub VistaQ(WhereToGo)" ascii //weight: 1
        $x_1_7 = {46 6f 72 20 45 61 63 68 20 4b 65 79 20 49 6e 20 70 75 74 41 72 72 61 79 42 69 67 4c 69 73 74 [0-21] 4b 69 6c 6c 20 4b 65 79 [0-16] 4e 65 78 74 20 4b 65 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_EB_2147763707_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.EB!MTB"
        threat_id = "2147763707"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Dim vSpeed As Integer" ascii //weight: 1
        $x_1_2 = "Dim vLicensePlate As String" ascii //weight: 1
        $x_1_3 = "car.SpecialFolders" ascii //weight: 1
        $x_1_4 = "cmd_cari.Enabled = True" ascii //weight: 1
        $x_1_5 = "TBT = TBT + \"\" + \"\"" ascii //weight: 1
        $x_1_6 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 53 70 65 65 64 28 29 20 41 73 20 49 6e 74 65 67 65 72 [0-16] 53 70 65 65 64 20 3d 20 76 53 70 65 65 64 02 00 45 6e 64 20 50 72 6f 70 65 72 74 79}  //weight: 1, accuracy: Low
        $x_1_7 = {49 66 20 4c 65 6e 28 6c 70 29 20 3c 3e 20 36 20 54 68 65 6e 20 45 72 72 2e 52 61 69 73 65 20 28 78 6c 45 72 72 56 61 6c 75 65 29 [0-16] 76 4c 69 63 65 6e 73 65 50 6c 61 74 65 20 3d 20 6c 70 02 00 45 6e 64 20 50 72 6f 70 65 72 74 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_EC_2147763708_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.EC!MTB"
        threat_id = "2147763708"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Public Function RedButton(dImmer As Double)" ascii //weight: 1
        $x_1_2 = "Dim SpecialPath As String" ascii //weight: 1
        $x_1_3 = {54 42 54 20 3d 20 50 52 50 02 00 54 42 54 20 3d 20 54 42 54 20 2b}  //weight: 1, accuracy: Low
        $x_1_4 = "TBT = TSPIP.ExpandEnvironmentStrings(TBT)" ascii //weight: 1
        $x_1_5 = "ChDir (Form0.TextBox1.Tag + \"\")" ascii //weight: 1
        $x_1_6 = "Call Err.Raise(9999, , Message)" ascii //weight: 1
        $x_1_7 = "Call Check(Shel.l32.CurrentDirectory, b(1).CurrentDirectory)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_EC_2147763708_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.EC!MTB"
        threat_id = "2147763708"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Public Declare Function code2 Lib \"kernel32.dll\" Alias \"SetDefaultDllDirectories\" (ByVal DirectoryFlags As Long) As Long" ascii //weight: 1
        $x_1_2 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 41 73 20 57 68 65 72 65 54 6f 47 6f 2c 20 4c 6f 63 61 6c 3a 3d 46 61 6c 73 65 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d 33 20 2a 20 37 20 2b 20 33 20 2a 20 37 20 2b 20 39 [0-8] 44 6f 45 76 65 6e 74 73 [0-8] 44 6f 45 76 65 6e 74 73 [0-8] 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 43 6c 6f 73 65 02 00 44 6f 45 76 65 6e 74 73}  //weight: 1, accuracy: Low
        $x_1_3 = "Public Function ExChangeMoney()" ascii //weight: 1
        $x_1_4 = "Lrigat = UserForm1.Label11.Tag" ascii //weight: 1
        $x_1_5 = "Range(\"L2\").Formula = \"$0\"" ascii //weight: 1
        $x_1_6 = "Range(\"M2\").Formula = \"0\"" ascii //weight: 1
        $x_1_7 = "Range(\"N2\").Formula = \"0%\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_ED_2147763872_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.ED!MTB"
        threat_id = "2147763872"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Public Declare Function bemax Lib \"rgoc1.dll\" () As Integer" ascii //weight: 1
        $x_1_2 = "Public Declare PtrSafe Function bemax Lib \"rgoc2.dll\" () As Integer" ascii //weight: 1
        $x_1_3 = "ofbl = ofbl + \"\\rgoc\"" ascii //weight: 1
        $x_1_4 = "dershlep = \"\" & Form0.TextBox3.Tag" ascii //weight: 1
        $x_1_5 = "Range(\"E2\").Formula = \"$0\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_EE_2147763873_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.EE!MTB"
        threat_id = "2147763873"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ctackPip = liquidOne & \".zip\"" ascii //weight: 1
        $x_1_2 = "PublicResumEraseByArrayList ofbl + \"*\", ctackPip, dershlep + UserForm1.Label1.Tag" ascii //weight: 1
        $x_1_3 = "liquidOne = Form0.TextBox1.Tag + \"\\academ\"" ascii //weight: 1
        $x_1_4 = "var2bin ctackPip + \"\", data" ascii //weight: 1
        $x_1_5 = "ggg.UserForm1.Hide" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_EF_2147763924_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.EF!MTB"
        threat_id = "2147763924"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FileCopy Src & \"\\\" & f, Dst & \"\\\" & f" ascii //weight: 1
        $x_1_2 = "OPath = Replace(Trim(Command$), \"\"\"\", \"\")" ascii //weight: 1
        $x_1_3 = "targetEXE = App.path & \"\\\" & App.EXEName & \".exe\"" ascii //weight: 1
        $x_1_4 = "tempPath = VBA.Environ(\"temp\")" ascii //weight: 1
        $x_1_5 = "ctackPip = liquidOne & Page11.Range(\"B115\").value" ascii //weight: 1
        $x_1_6 = "Lrigat = UserForm1.Label11.Tag" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_EG_2147763925_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.EG!MTB"
        threat_id = "2147763925"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "liquidOne = Form0.TextBox1.Tag + \"\\academ\"" ascii //weight: 1
        $x_1_2 = "liquidOne = liquidOne + \"l.xlsx\"" ascii //weight: 1
        $x_1_3 = "ofbl = Form0.TextBox1.Tag" ascii //weight: 1
        $x_1_4 = "ctackPip, dershlep & UserForm1.Label1.Tag" ascii //weight: 1
        $x_1_5 = "Range(\"D2\").Formula = \"$0\"" ascii //weight: 1
        $x_1_6 = "+ Form0.TextBox3.Tag" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_EH_2147763926_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.EH!MTB"
        threat_id = "2147763926"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PRP = \"%\" + Form0.TextBox1.Tag" ascii //weight: 1
        $x_1_2 = "TBT = TBT + \"%\"" ascii //weight: 1
        $x_1_3 = "TBT = CallByName(TSPIP, \"ExpandEnvironmentStrings\", VbMethod, TBT)" ascii //weight: 1
        $x_1_4 = "Form0.TextBox1.Tag = TBT" ascii //weight: 1
        $x_1_5 = "s = car.CheckCar(TSPIP, Form0.TextBox3.ControlTipText & \"\")" ascii //weight: 1
        $x_1_6 = "s = \"Minor health problems\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_EI_2147771170_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.EI!MTB"
        threat_id = "2147771170"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 6f 64 75 6c 65 35 2e 52 65 64 42 75 74 74 6f 6e 20 31 39 39 39 39 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = {44 6f 45 76 65 6e 74 73 02 00 44 6f 45 76 65 6e 74 73 02 00 45 78 43 68 61 6e 67 65 4d 6f 6e 65 79 02 00 44 6f 45 76 65 6e 74 73 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 29 20 41 73 20 53 74 72 69 6e 67 [0-8] 4c 69 63 65 6e 73 65 50 6c 61 74 65 20 3d 20 76 4c 69 63 65 6e 73 65 50 6c 61 74 65 02 00 45 6e 64 20 50 72 6f 70 65 72 74 79}  //weight: 1, accuracy: Low
        $x_1_4 = {50 75 62 6c 69 63 20 53 75 62 20 56 69 73 74 61 51 28 57 68 65 72 65 54 6f 47 6f 29 [0-4] 44 6f 45 76 65 6e 74 73}  //weight: 1, accuracy: Low
        $x_1_5 = "Public Function ExChangeMoney()" ascii //weight: 1
        $x_1_6 = {44 69 6d 20 74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 49 20 41 73 20 42 6f 6f 6c 65 61 6e [0-8] 44 69 6d 20 74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 51 20 41 73 20 42 6f 6f 6c 65 61 6e}  //weight: 1, accuracy: Low
        $x_1_7 = "TSPIP, Form0.TextBox3.ControlTipText & \"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_EJ_2147771277_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.EJ!MTB"
        threat_id = "2147771277"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sOfbl = ofbl + \".zip\"" ascii //weight: 1
        $x_1_2 = "PublicResumEraseByArrayList ofbl + \"*\", sOfbl, ctackPip, Form0.TextBox3.Tag + \"\\libReq*\", dershlep & UserForm1.Label1.Tag" ascii //weight: 1
        $x_1_3 = "liquidOne = liquidOne + \"l.xlsx\"" ascii //weight: 1
        $x_1_4 = "ofbl = Form0.TextBox1.Tag" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_EK_2147771278_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.EK!MTB"
        threat_id = "2147771278"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ofbl = ofbl + \"\\libReq\"" ascii //weight: 1
        $x_1_2 = "liquidOne = Form0.TextBox1.Tag + \"\\academ\"" ascii //weight: 1
        $x_1_3 = "VistaQ liquidOne" ascii //weight: 1
        $x_1_4 = "FileCopy Source:=liquidOne, Destination:=ctackPip" ascii //weight: 1
        $x_1_5 = "Lrigat = UserForm1.Label11.Caption" ascii //weight: 1
        $x_1_6 = "DestinationKat.CopyHere harvest.Items.Item(\"\" + Lrigat)" ascii //weight: 1
        $x_1_7 = "Range(\"E2\").Formula = \"$0\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_EL_2147771279_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.EL!MTB"
        threat_id = "2147771279"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PRP = \"%\" + Form0.TextBox1.Tag" ascii //weight: 1
        $x_1_2 = "TBT = TBT + \"\" + \"\"" ascii //weight: 1
        $x_1_3 = "TBT = TBT + \"%\"" ascii //weight: 1
        $x_1_4 = "TBT = TSPIP.ExpandEnvironmentStrings(TBT)" ascii //weight: 1
        $x_1_5 = "s = car.CheckCar(TSPIP, Form0.TextBox3.ControlTipText & \"\")" ascii //weight: 1
        $x_1_6 = "ChDir (Form0.TextBox1.Tag + \"\")" ascii //weight: 1
        $x_1_7 = "If tooolsetChunkI And j = Count And C <> \"\"\"\" Then GetP.aram = GetP." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_EM_2147771345_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.EM!MTB"
        threat_id = "2147771345"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Public Property Get CheckCar(car As Variant, Drive As String)" ascii //weight: 1
        $x_1_2 = "CheckCar = car.SpecialFolders(\"\" & Drive)" ascii //weight: 1
        $x_1_3 = "Public Property Get SpecialFolders() As String" ascii //weight: 1
        $x_1_4 = "LicensePlate = vLicensePlate" ascii //weight: 1
        $x_1_5 = "Public Property Let LicensePlate(lp As String)" ascii //weight: 1
        $x_1_6 = "If Len(lp) <> 6 Then Err.Raise (xlErrValue)" ascii //weight: 1
        $x_1_7 = "vLicensePlate = lp" ascii //weight: 1
        $x_1_8 = "Public Property Get Speed() As Integer" ascii //weight: 1
        $x_1_9 = "Speed = vSpeed" ascii //weight: 1
        $x_1_10 = "sOfbl = \"\"\"\" + sOfbl & \"\"\",\"\"\"" ascii //weight: 1
        $x_1_11 = "tooolsetChunkI = False" ascii //weight: 1
        $x_1_12 = "tooolsetChunkQ = False" ascii //weight: 1
        $x_1_13 = {4d 6f 64 75 6c 65 35 2e 52 65 64 42 75 74 74 6f 6e 20 31 39 39 39 39 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_14 = "Public Function RedButton(dImmer As Double)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_EN_2147771436_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.EN!MTB"
        threat_id = "2147771436"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ctackPip = liquidOne & \".zip\"" ascii //weight: 1
        $x_1_2 = "liquidOne = Form0.TextBox1.Tag + \"\\academ\"" ascii //weight: 1
        $x_1_3 = "liquidOne = liquidOne + \"l.xlsx\"" ascii //weight: 1
        $x_1_4 = "ofbl = Form0.TextBox1.Tag" ascii //weight: 1
        $x_1_5 = "ofbl = ofbl + \"\\libReq\"" ascii //weight: 1
        $x_1_6 = {50 75 62 6c 69 63 20 53 75 62 20 56 69 73 74 61 51 28 57 68 65 72 65 54 6f 47 6f 29 [0-4] 44 6f 45 76 65 6e 74 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_GraceWire_EO_2147771437_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/GraceWire.EO!MTB"
        threat_id = "2147771437"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "GraceWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sOfbl = ofbl + \".zip\"" ascii //weight: 1
        $x_1_2 = "PublicResumEraseByArrayList ofbl + \"*\", ctackPip, Form0.TextBox3.Tag + \"\\libReq*\", sOfbl, dershlep & UserForm1.Label1.Tag" ascii //weight: 1
        $x_1_3 = "FileCopy Source:=liquidOne, Destination:=ctackPip" ascii //weight: 1
        $x_1_4 = "Lrigat = UserForm1.Label11.Caption" ascii //weight: 1
        $x_1_5 = "Range(\"A2\").Formula = \"$0\"" ascii //weight: 1
        $x_1_6 = "Composition dershlep + UserForm1.Label1.Tag + \"\" & \"\", sOfbl, NumBForRead" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_O97M_IcedID_SS_2147759872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/IcedID.SS!MTB"
        threat_id = "2147759872"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"<div id='content'>fTtlc29sYy5" ascii //weight: 1
        $x_1_2 = "('/+9876543210zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA'));" ascii //weight: 1
        $x_1_3 = "tiveXObject(" ascii //weight: 1
        $x_1_4 = "= 'charAt';for(i=0;i<64;i++)" ascii //weight: 1
        $x_1_5 = "for(x=0;x<L;x++)" ascii //weight: 1
        $x_1_6 = ".split('').reverse().join('')" ascii //weight: 1
        $x_1_7 = ".split('|');var" ascii //weight: 1
        $x_1_8 = "(x)];b=(b<<6)+c;l+=6;while(l>=8){((a=(b>>>(l-=8))&0xff)||" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_IcedID_SS_2147759872_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/IcedID.SS!MTB"
        threat_id = "2147759872"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 72 65 76 65 72 73 65 64 54 65 78 74 20 26 20 4d 69 64 28 [0-21] 2c 20 28 6c 65 6e 67 74 68 20 2d 20 69 29 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_2 = ".Documents.Add.VBProject.VBComponents(\"ThisDocument\").CodeModule" ascii //weight: 1
        $x_1_3 = "memoryMainButton = \"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\\" & Application.Version & \"\\Word\\Security\\AccessVBOM" ascii //weight: 1
        $x_1_4 = {53 75 62 20 76 61 72 4d 61 69 6e 28 29 [0-3] 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 52 65 67 57 72 69 74 65 20 6d 65 6d 6f 72 79 4d 61 69 6e 42 75 74 74 6f 6e 2c 20 31 2c 20 22 52 45 47 5f 44 57 4f 52 44 22 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = "VB_Name = \"counterCopyPaste" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_IcedID_SS_2147759872_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/IcedID.SS!MTB"
        threat_id = "2147759872"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 72 6d 2e 66 66 66 20 22 68 74 74 70 3a 2f 2f 6d 33 33 78 61 33 2e 63 6f 6d 2f 68 62 6f 6e 65 62 2f 73 6f 6c 39 35 2e 70 68 70 3f 6c 3d 70 75 6f 6d [0-2] 2e 63 61 62 22 2c 20 4f}  //weight: 2, accuracy: Low
        $x_2_2 = {66 72 6d 2e 66 66 66 20 22 68 74 74 70 3a 2f 2f 31 62 77 73 6c 34 2e 63 6f 6d 2f 68 62 6f 6e 65 62 2f 73 6f 6c 39 35 2e 70 68 70 3f 6c 3d 70 75 6f 6d [0-2] 2e 63 61 62 22 2c 20 4f}  //weight: 2, accuracy: Low
        $x_2_3 = {66 72 6d 2e 66 66 66 20 22 68 74 74 70 3a 2f 2f 38 30 34 67 74 64 2e 63 6f 6d 2f 68 62 6f 6e 65 62 2f 73 6f 6c 39 35 2e 70 68 70 3f 6c 3d 70 75 6f 6d [0-2] 2e 63 61 62 22 2c 20 4f}  //weight: 2, accuracy: Low
        $x_2_4 = {66 72 6d 2e 66 66 66 20 22 68 74 74 70 3a 2f 2f 75 68 71 39 34 33 2e 63 6f 6d 2f 68 62 6f 6e 65 62 2f 73 6f 6c 39 35 2e 70 68 70 3f 6c 3d 70 75 6f 6d [0-2] 2e 63 61 62 22 2c 20 4f}  //weight: 2, accuracy: Low
        $x_2_5 = {66 72 6d 2e 66 66 66 20 22 68 74 74 70 3a 2f 2f 6e 39 69 39 65 70 2e 63 6f 6d 2f 68 62 6f 6e 65 62 2f 73 6f 6c 39 35 2e 70 68 70 3f 6c 3d 70 75 6f 6d [0-2] 2e 63 61 62 22 2c 20 4f}  //weight: 2, accuracy: Low
        $x_2_6 = {66 72 6d 2e 66 66 66 20 22 68 74 74 70 3a 2f 2f 6e 6d 35 6f 69 30 2e 63 6f 6d 2f 68 62 6f 6e 65 62 2f 73 6f 6c 39 35 2e 70 68 70 3f 6c 3d 70 75 6f 6d [0-2] 2e 63 61 62 22 2c 20 4f}  //weight: 2, accuracy: Low
        $x_1_7 = {66 72 6d 2e 66 66 66 20 22 68 74 74 70 3a 2f 2f [0-15] 2f 68 62 6f 6e 65 62 2f 73 6f 6c 39 35 2e 70 68 70 3f 6c 3d 70 75 6f 6d [0-2] 2e 63 61 62 22 2c 20 4f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_O97M_IcedID_SS_2147759872_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/IcedID.SS!MTB"
        threat_id = "2147759872"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sizeNamespaceMemory = \"<div id='content'>fTtlc29sYy5ub2l0cGFDeWFycmE7KTIgLCJncGouZXNhYmF0YURlbGJhVHhlZG5pXFxjaWxidXBcXHNyZXN1XFw6YyIoZWxpZm90ZXZhcy5ub2l0cGFDeWFy" ascii //weight: 2
        $x_2_2 = "= \"<div id='content'>fTtlc29sYy50eGVUcnRwOykyICwiZ3BqLnlyb21lTWVnYXJvdHNcXGNpbGJ1cFxcc3Jlc3VcXDpjIihlbGlmb3RldmFzLnR4ZVRydHA7KXlkb2Jlc25vcHNlci5lbHRpVHJlZmZ1Qm5lb" ascii //weight: 2
        $x_2_3 = "= \"<div id='content'>fTtlc29sYy5wbWVUeGVkbklzc2FsYzspMiAsImdwai5uaWFNV3RmZWxcXGNpbGJ1cFxcc3Jlc3VcXDpjIihlbGlmb3RldmFzLnBtZVR4ZWRuSXNzYWxjOyl5ZG9iZXNub3" ascii //weight: 2
        $x_2_4 = "= \"<div id='content'>fTtlc29sYy5ldm9tZVJ4b2J0eGVUbm9pdHBlY3hlOykyICwiZ3BqLmVjYXBzZW1hTnJhdlxcY2lsYnVwXFxzcmVzdVxcOmMiKGVsaWZvdGV2YXMuZXZvbWVSeG9idHhlVG5vaXRwZWN4" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_O97M_IcedID_RA_2147789282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/IcedID.RA!MTB"
        threat_id = "2147789282"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 77 69 6e 64 6f 77 5f 6f 70 65 6e 28 [0-31] 29 0d 0a 53 65 74 20 [0-31] 20 3d 20 4e 65 77 20 49 57 73 68 52 75 6e 74 69 6d 65 4c 69 62 72 61 72 79 2e 57 73 68 53 68 65 6c 6c 0d 0a 01 2e 72 75 6e 20 22 73 63 72 69 70 74 72 75 6e 6e 65 72 20 2d 61 70 70 76 73 63 72 69 70 74 20 22 20 26 20 00 2c 20 32}  //weight: 1, accuracy: Low
        $x_1_2 = {53 75 62 20 77 69 6e 64 6f 77 5f 6f 70 65 6e 28 [0-31] 29 0d 0a 53 65 74 20 [0-31] 20 3d 20 4e 65 77 20 49 57 73 68 52 75 6e 74 69 6d 65 4c 69 62 72 61 72 79 2e 57 73 68 53 68 65 6c 6c 0d 0a 01 2e 72 75 6e 20 00 2c 20 32}  //weight: 1, accuracy: Low
        $x_1_3 = {50 75 62 6c 69 63 20 53 75 62 20 [0-15] 28 [0-31] 2c 20 [0-15] 29 0d 0a 01 20 3d 20 22 2e 22 20 26 20 01 20 26 20 02 0d 0a 4f 70 65 6e 20 01 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 0d 0a 50 72 69 6e 74 20 23 31 2c 20 52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2c 20 22 [0-15] 22 2c 20 22 22 29 0d 0a 43 6c 6f 73 65 20 23 31 0d 0a 77 69 6e 64 6f 77 5f 6f 70 65 6e 20 01 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_O97M_IcedID_RA_2147789282_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/IcedID.RA!MTB"
        threat_id = "2147789282"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {53 75 62 20 77 69 6e 64 6f 77 5f 6f 70 65 6e 28 [0-31] 29 0d 0a 53 65 74 20 [0-31] 20 3d 20 4e 65 77 20 49 57 73 68 52 75 6e 74 69 6d 65 4c 69 62 72 61 72 79 2e 57 73 68 53 68 65 6c 6c 0d 0a 01 2e 72 75 6e 20 22 73 63 72 69 70 74 72 75 6e 6e 65 72 20 2d 61 70 70 76 73 63 72 69 70 74 20 22 20 26 20 00 2c 20 32}  //weight: 5, accuracy: Low
        $x_5_2 = {53 75 62 20 77 69 6e 64 6f 77 5f 6f 70 65 6e 28 [0-31] 29 0d 0a 53 65 74 20 [0-31] 20 3d 20 4e 65 77 20 49 57 73 68 52 75 6e 74 69 6d 65 4c 69 62 72 61 72 79 2e 57 73 68 53 68 65 6c 6c 0d 0a 01 2e 72 75 6e 20 00 2c 20 32}  //weight: 5, accuracy: Low
        $x_1_3 = {50 75 62 6c 69 63 20 53 75 62 20 [0-15] 28 [0-31] 2c 20 [0-15] 29 0d 0a 01 20 3d 20 22 2e 22 20 26 20 01 20 26 20 02 0d 0a 4f 70 65 6e 20 01 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 0d 0a 50 72 69 6e 74 20 23 31 2c 20 52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2c 20 22 [0-15] 22 2c 20 22 22 29 0d 0a 43 6c 6f 73 65 20 23 31 0d 0a 77 69 6e 64 6f 77 5f 6f 70 65 6e 20 01 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = {50 75 62 6c 69 63 20 53 75 62 20 61 75 74 6f 4f 70 65 6e 28 29 0d 0a [0-10] 20 22 22 2c 20 22 48 54 41 22 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 [0-31] 28 29 0d 0a 00 20 3d 20 52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2c 20 22 [0-7] 22 2c 20 22 22 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 0d 0a 50 75 62 6c 69 63 20 53 75 62 20 [0-15] 28 [0-31] 2c 20 [0-31] 29 0d 0a 04 20 3d 20 22 2e 22 20 26 20 04 20 26 20 05 0d 0a 4f 70 65 6e 20 04 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 0d 0a 50 72 69 6e 74 20 23 31 2c 20 00 0d 0a 43 6c 6f 73 65 20 23 31 0d 0a 77 69 6e 64 6f 77 5f 6f 70 65 6e 20 04 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_O97M_IcedID_PDIE_2147829326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/IcedID.PDIE!MTB"
        threat_id = "2147829326"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=strreverse(activedocument.customdocumentproperties(strinput))endfunctionfunction(" ascii //weight: 1
        $x_1_2 = ".remove(vzldcdl9a(\"iqqiru2\"))()." ascii //weight: 1
        $x_1_3 = ".remove(lamt7w1fq9(\"szjwykb2\"))()." ascii //weight: 1
        $x_1_4 = "oyhbmhbl\"),vbget,vzldcdl9a(\"zudlf2tbe\"))" ascii //weight: 1
        $x_1_5 = "bsappujyw\"),vbget,lamt7w1fq9(\"hba7jae\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_O97M_IcedID_PDIG_2147829633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/IcedID.PDIG!MTB"
        threat_id = "2147829633"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 73 74 72 69 6e 70 75 74 3d 61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 2e 63 75 73 74 6f 6d 64 6f 63 75 6d 65 6e 74 70 72 6f 70 65 72 74 69 65 73 28 73 74 72 69 6e 70 75 74 29 [0-10] 3d 22 22 66 6f 72 6b 3d 30 74 6f 6c 65 6e 28 73 74 72 69 6e 70 75 74 29}  //weight: 1, accuracy: Low
        $x_1_2 = {76 62 67 65 74 2c 29 65 6c 73 65 73 65 74 3d 28 28 29 2c 29 65 6e 64 69 66 73 65 74 3d 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 28 29 3d [0-1] 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 28 29 3d}  //weight: 1, accuracy: Low
        $x_1_3 = ".value)else=((sxinchibv(\"at7lldrw\")).value)" ascii //weight: 1
        $x_1_4 = ".value)else=((zfp7svflci(\"jav3eo2s\")).value)" ascii //weight: 1
        $x_1_5 = "=0to()-1step2=/2()=255-(&(,)&(,+1))next=endfunctionfunction(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_O97M_IcedID_PDIH_2147829791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/IcedID.PDIH!MTB"
        threat_id = "2147829791"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 73 74 72 69 6e 70 75 74 3d 61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 2e 63 75 73 74 6f 6d 64 6f 63 75 6d 65 6e 74 70 72 6f 70 65 72 74 69 65 73 28 73 74 72 69 6e 70 75 74 29 [0-32] 3d 22 22 66 6f 72 6b 3d 30 74 6f 6c 65 6e 28 73 74 72 69 6e 70 75 74 29}  //weight: 1, accuracy: Low
        $x_1_2 = "vbget,)elseset=((),)endifset=endfunction" ascii //weight: 1
        $x_1_3 = "=0to()-1step2=/2()=255-(&(,)&(,+1))next=endfunction" ascii //weight: 1
        $x_1_4 = "0&,0&,0&,0&redim(1)endsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_IcedID_STA_2147898460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/IcedID.STA!MTB"
        threat_id = "2147898460"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"tiveXObject(exceptionNamespaceException));" ascii //weight: 1
        $x_1_2 = "= \"ng.fromCharCode; var L=s.length;var databaseLink = 'charAt';" ascii //weight: 1
        $x_1_3 = "= \"arTableLeft(clearCollectionCounter){return clearCollectionCounter.split('').reverse().join('');" ascii //weight: 1
        $x_1_4 = "= \"').innerHTML;var classGlobalConvert = classGlobalConvert.split('|')" ascii //weight: 1
        $x_1_5 = "= \"textboxCollection(tmpCount)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


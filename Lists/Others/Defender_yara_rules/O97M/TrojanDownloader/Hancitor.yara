rule TrojanDownloader_O97M_Hancitor_B_2147729788_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Hancitor.B"
        threat_id = "2147729788"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell StrConv(DecodeBase64(\"Y21kLmV4ZSAvYyAgcGluZyBsb2NhbGhvc3QgLW4gMTAwICYmIA==\")" ascii //weight: 1
        $x_1_2 = "StrConv(DecodeBase64(\"XDYucGlm\"), vbUnicode), vbHide" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Hancitor_C_2147743459_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Hancitor.C!MTB"
        threat_id = "2147743459"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "& \"F.wll\"" ascii //weight: 1
        $x_1_2 = {3d 20 31 20 54 6f 20 4c 65 6e 28 [0-20] 29 20 53 74 65 70 20 32 3a 20 2e 57 72 69 74 65 20 43 68 72 28 43 42 79 74 65 28 22 26 48 22 20 26 20 4d 69 64 28 [0-20] 2c 20 6c 70 2c 20 32 29 29 29 3a 20 4e 65 78 74 3a 20 45 6e 64 20 57 69 74 68 3a 20 6f 62 6a 46 69 6c 65 2e 43 6c 6f 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = "= Environ(\"APPDATA\") & \"\\Microsoft\\Word\\Startup\\\"" ascii //weight: 1
        $x_1_4 = "MsgBox \"The document is protected, you will need to specify a password to unlock.\"" ascii //weight: 1
        $x_1_5 = "\"http://" ascii //weight: 1
        $x_1_6 = ".CreateFolder (" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Hancitor_D_2147743905_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Hancitor.D!MTB"
        threat_id = "2147743905"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "& \"F.wll\"" ascii //weight: 1
        $x_1_2 = {3d 20 31 20 54 6f 20 4c 65 6e 28 [0-20] 29 20 53 74 65 70 20 32 3a 20 2e 57 72 69 74 65 20 43 68 72 28 43 42 79 74 65 28 22 26 48 22 20 26 20 4d 69 64 28 [0-20] 2c 20 6c 70 2c 20 32 29 29 29 3a 20 4e 65 78 74 3a 20 45 6e 64 20 57 69 74 68 3a 20 6f 62 6a 46 69 6c 65 2e 43 6c 6f 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = "= Environ(\"A\" + \"PP\" + \"DA\" + \"TA\") &" ascii //weight: 1
        $x_1_4 = "Object(\"w\" + \"i\" + \"n\" + \"mg\" + \"m\" + \"ts\" + \":W\" + \"i\" + \"n3\" + \"2_\" + \"P\" + \"r\" + \"oc\" + \"e\" + \"ss\")" ascii //weight: 1
        $x_1_5 = "\"Th\" + \"e d\" + \"oc\" + \"um\" + \"ent \" + \"is\" + \" p\" + \"ro\" + \"te\" + \"ct\" + \"ed\"" ascii //weight: 1
        $x_1_6 = ".CreateFolder (" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Hancitor_HA_2147768403_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Hancitor.HA!MTB"
        threat_id = "2147768403"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ntgs) & \"Loc\" & \"al\\Te\" & \"mp\", vbDirectory) =" ascii //weight: 1
        $x_1_2 = "Getme(RootPath As String)" ascii //weight: 1
        $x_1_3 = "= fso.GetFolder(asdf)" ascii //weight: 1
        $x_1_4 = "Dir(RootPath & \"\\22.mp4\")" ascii //weight: 1
        $x_1_5 = "Getme(vhhs.Path)" ascii //weight: 1
        $x_1_6 = "Path & \"\\W0rd.dll\") = \"\"" ascii //weight: 1
        $x_1_7 = "Call lka(RootPath)" ascii //weight: 1
        $x_1_8 = "Name UUu & \"\\22.mp4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Hancitor_VIS_2147772914_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Hancitor.VIS!MTB"
        threat_id = "2147772914"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dir(RootPath & \"\\0fiasS.tmp\")" ascii //weight: 1
        $x_1_2 = "Dir(vzxx & \"\\W0rd.dll\") = \"\"" ascii //weight: 1
        $x_1_3 = "0fiasS.t\" & \"mp\" As ActiveDocument.AttachedTemplate.Path & \"\\\" & \"W0rd.dll\"" ascii //weight: 1
        $x_1_4 = "Call regsrva.ShellExecute(fa, yy, \" \", SW_SHOWNORMAL)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Hancitor_EOAC_2147785052_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Hancitor.EOAC!MTB"
        threat_id = "2147785052"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pattison = \"\\ier.d\"" ascii //weight: 1
        $x_1_2 = "Call Search(MyFSO.GetFolder(asda), hdv)" ascii //weight: 1
        $x_1_3 = "bbbb & cvzz, vcbc & pattison & \"ll\"" ascii //weight: 1
        $x_1_4 = "bbbb = bbbb & \"u\" & dfgdgdg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Hancitor_EOAH_2147787370_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Hancitor.EOAH!MTB"
        threat_id = "2147787370"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& \"\\qq.doc\"," ascii //weight: 1
        $x_1_2 = "Call Search(MyFSO.GetFolder(asda), hdv)" ascii //weight: 1
        $x_1_3 = "Dim dfgdgdg" ascii //weight: 1
        $x_1_4 = "Dim uuuuc" ascii //weight: 1
        $x_1_5 = "Call nam(hdv)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Hancitor_EOAI_2147787371_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Hancitor.EOAI!MTB"
        threat_id = "2147787371"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qq.doc\"," ascii //weight: 1
        $x_1_2 = "pls = fffs" ascii //weight: 1
        $x_1_3 = "If Dir(Left(uuuuc, ntgs) & ewrwsdf, vbDirectory) = \"\" Then" ascii //weight: 1
        $x_1_4 = "Call ThisDocument.hdhdd(Left(uuuuc, ntgs) & ewrwsdf)" ascii //weight: 1
        $x_1_5 = "ewrwsdf = \"Local/Temp\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Hancitor_SS_2147805778_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Hancitor.SS!MTB"
        threat_id = "2147805778"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "If Dir(Options.DefaultFilePath(wdUserTemplatesPath) & \"\\iff.bin\", vbDirectory) = \"\" Then" ascii //weight: 1
        $x_1_2 = {43 61 6c 6c 20 [0-8] 44 6f 63 75 6d 65 6e 74 73 2e 4f 70 65 6e 20 66 69 6c 65 4e 61 6d 65 3a 3d 76 78 63 20 26 20 22 68 65 6c 70 2e 64 6f 63 22 2c 20 50 61 73 73 77 6f 72 64 44 6f 63 75 6d 65 6e 74 3a 3d 22 64 6f 6e 74 74 6f 75 63 68 6d 65 22 [0-3] 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
        $x_1_3 = {76 78 63 20 3d 20 76 78 63 20 26 20 22 68 74 74 22 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = {76 78 63 20 3d 20 76 78 63 20 26 20 22 70 3a 2f 2f 22 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = {76 78 63 20 3d 20 76 78 63 20 26 20 22 64 69 75 61 72 35 2e 72 75 2f 22 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Hancitor_SML_2147811698_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Hancitor.SML!MTB"
        threat_id = "2147811698"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "klx = \"t\"" ascii //weight: 1
        $x_1_2 = "Call mm(\"h\" & \"t\" & klx)" ascii //weight: 1
        $x_1_3 = "vv = \"p.\" & vf" ascii //weight: 1
        $x_1_4 = "& \"\\moexx\" & plf & \"b\" & \"i\" & \"n\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Hancitor_HB_2147898429_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Hancitor.HB!MTB"
        threat_id = "2147898429"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Dir(RootPath & \"\\22.mp4\")" ascii //weight: 1
        $x_1_2 = {3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 [0-10] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {50 61 74 68 20 26 20 22 5c [0-5] 2e 64 6c 6c 2c 53 74 61 72 74 22 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 28 22 72 75 6e 64 22 20 26 20 22 6c 6c [0-5] 33 32 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_5 = "ntgs) & \"Loc\" & \"al\\Te\" & \"mp\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


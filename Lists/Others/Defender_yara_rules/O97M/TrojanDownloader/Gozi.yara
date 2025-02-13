rule TrojanDownloader_O97M_Gozi_YA_2147759259_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.YA!MTB"
        threat_id = "2147759259"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub autoopen()" ascii //weight: 1
        $x_1_2 = "Call URLDownloadToFile" ascii //weight: 1
        $x_1_3 = "http://9bgnq.com/iz5/yaca.php" ascii //weight: 1
        $x_1_4 = "http://d7uap.com/iz5/yaca.php?l=http://tze1.cab" ascii //weight: 1
        $x_1_5 = "http://p7hne.com/iz5/yaca.php?l=tze3.cab\", JK" ascii //weight: 1
        $x_1_6 = "C.tmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Gozi_YB_2147759817_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.YB!MTB"
        threat_id = "2147759817"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 33 33 78 61 33 2e 63 6f 6d 2f 68 62 6f 6e 65 62 2f 73 6f 6c [0-4] 2e 70 68 70 3f 6c 3d 70 75 6f 6d}  //weight: 1, accuracy: Low
        $x_1_2 = "C8.tmp" ascii //weight: 1
        $x_1_3 = "Xd As String = \"regsv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_PGB_2147763696_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.PGB!MTB"
        threat_id = "2147763696"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Environ$(\"USERPROFILE\") + \"\\ha1\"" ascii //weight: 1
        $x_1_2 = "GG.create SR4 + \" \" + STP + \".txt" ascii //weight: 1
        $x_1_3 = "GG.create SR3 + \" \" + STP + \".pdf" ascii //weight: 1
        $x_1_4 = "Result2: Sleep 6000" ascii //weight: 1
        $x_1_5 = "Set GG = CreateObject(SR1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_URL_2147765847_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.URL!MTB"
        threat_id = "2147765847"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://log.lenssexy.com/installazione.dll" ascii //weight: 1
        $x_1_2 = "asFsqkD.dll" ascii //weight: 1
        $x_1_3 = "C:\\zWGQWSe" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_5 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_XTW_2147766099_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.XTW!MTB"
        threat_id = "2147766099"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://service.technosolarsystems.com/installazione.dll" ascii //weight: 1
        $x_1_2 = "zlpPEBu.dll" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_4 = "C:\\NKhDbhd\\psHcenx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_AGN_2147766263_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.AGN!MTB"
        threat_id = "2147766263"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://blogilive.bar/installa.dll" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "C:\\ujgaspN\\iHNJVY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_DEC_2147767647_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.DEC!MTB"
        threat_id = "2147767647"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://agentsystems.bar/opzionalla.dll" ascii //weight: 1
        $x_1_2 = "C:\\GmHMUKp\\yzxDagn" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_DEC_2147767647_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.DEC!MTB"
        threat_id = "2147767647"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://agentsystems.cyou/opzionalla.dll" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "C:\\DSLucfz\\cguranN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_PZI_2147767704_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.PZI!MTB"
        threat_id = "2147767704"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://premiumclass.cyou/0pzional1a.dll" ascii //weight: 1
        $x_1_2 = "C:\\jHZlZXR\\jgDmxDy" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_INS_2147767721_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.INS!MTB"
        threat_id = "2147767721"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://premiumclass.bar/0pzional1a.dll" ascii //weight: 1
        $x_1_2 = "C:\\zZCgeNB\\WMDRbKK" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_LIV_2147768121_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.LIV!MTB"
        threat_id = "2147768121"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://liveswindows.casa/opzi0n1.dll0" ascii //weight: 1
        $x_1_2 = "C:\\yEoipTg\\fvzCtTi\\IbWLqzB.dll" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_LIU_2147768397_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.LIU!MTB"
        threat_id = "2147768397"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://liveswindows.cyou/opzi0n1.dll" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "C:\\GQlylYz\\VUwevhl\\WGnqLnr.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_SS_2147769687_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.SS!MTB"
        threat_id = "2147769687"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set vsPhd = CreateObject(lGKLH(3) & \".\" & lGKLH(3) & \"request.5.1\")" ascii //weight: 1
        $x_1_2 = "CzlnP = Split(ActiveDocument.Shapes(1#).Title, jrIUN)" ascii //weight: 1
        $x_1_3 = "hEOpo = \"c:\\programdata\\GsXVM.pdf" ascii //weight: 1
        $x_1_4 = "Set lrRiF = CreateObject(ktaRk)" ascii //weight: 1
        $x_1_5 = "vsPhd.Open \"GET\", ZraUq(HUtly)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_AX_2147772996_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.AX!MTB"
        threat_id = "2147772996"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 43 3a 5c 75 73 65 72 73 5c 50 75 62 6c 69 63 5c [0-5] 2e 70 6e 67 22}  //weight: 1, accuracy: Low
        $x_1_2 = "= \"http\"" ascii //weight: 1
        $x_1_3 = ".Open \"GET\", UserForm1." ascii //weight: 1
        $x_1_4 = "ReferencePtr.Open" ascii //weight: 1
        $x_1_5 = "Shell@ (WindowClass + \"32 \" &" ascii //weight: 1
        $x_1_6 = {28 22 3a 2f 2f 6c 69 6e 65 73 74 61 74 73 2e 63 61 73 61 2f [0-10] 2e 6a 70 67 22 29}  //weight: 1, accuracy: Low
        $x_1_7 = "BufferConst.Send" ascii //weight: 1
        $x_1_8 = "ReferencePtr.Write BufferConst.ResponseBody" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_AY_2147773001_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.AY!MTB"
        threat_id = "2147773001"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"C:\\users\\Public\\256.png\"" ascii //weight: 1
        $x_1_2 = "= \"http\"" ascii //weight: 1
        $x_1_3 = ".Open \"GET\", UserForm1." ascii //weight: 1
        $x_1_4 = "Ptr.Open" ascii //weight: 1
        $x_1_5 = {53 68 65 6c 6c 40 20 28 ?? ?? ?? ?? ?? ?? 43 6c 61 73 73 20 2b 20 22 33 32 20 22 20 26}  //weight: 1, accuracy: Low
        $x_1_6 = "(\"://linestats.cyou/f0t0s.jpg\")" ascii //weight: 1
        $x_1_7 = {50 74 72 2e 57 72 69 74 65 20 [0-15] 2e 52 65 73 70 6f 6e 73 65 42 6f 64 79}  //weight: 1, accuracy: Low
        $x_1_8 = ".SaveToFile" ascii //weight: 1
        $x_1_9 = ".Send" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_AZ_2147773002_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.AZ!MTB"
        threat_id = "2147773002"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"C:\\users\\Public\\256.png\"" ascii //weight: 1
        $x_1_2 = "= \"http\"" ascii //weight: 1
        $x_1_3 = ".Open \"GET\", UserForm1." ascii //weight: 1
        $x_1_4 = {53 68 65 6c 6c 40 20 28 [0-15] 20 2b 20 22 33 32 20 22 20 26 20 55 73 65 72 46 6f 72 6d 31 2e}  //weight: 1, accuracy: Low
        $x_1_5 = {28 22 3a 2f 2f [0-10] 2e [0-5] 2f 66 30 74 30 73 2e 6a 70 67 22 29}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 57 72 69 74 65 20 [0-15] 2e 52 65 73 70 6f 6e 73 65 42 6f 64 79}  //weight: 1, accuracy: Low
        $x_1_7 = ".SaveToFile UserForm1." ascii //weight: 1
        $x_1_8 = ".Send" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_AW_2147773056_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.AW!MTB"
        threat_id = "2147773056"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"C:\\users\\Public\\2x.jpg\"" ascii //weight: 1
        $x_1_2 = "= \"http\"" ascii //weight: 1
        $x_1_3 = {28 22 3a 2f 2f [0-15] 2e [0-5] 2f 70 61 6e 30 72 61 6d 69 63 30 2e 6a 70 67 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {53 68 65 6c 6c 25 20 28 [0-15] 20 2b 20 22 20 22 20 26}  //weight: 1, accuracy: Low
        $x_1_5 = ".SaveToFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_PVZ_2147773934_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.PVZ!MTB"
        threat_id = "2147773934"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Private Sub CommandButton1_Click()" ascii //weight: 1
        $x_1_2 = "ListBox1.AddItem (Image1.ControlTipText)" ascii //weight: 1
        $x_1_3 = "ListBox1.AddItem (\"://" ascii //weight: 1
        $x_1_4 = ".com/header.jpg\")" ascii //weight: 1
        $x_1_5 = {49 6e 73 74 72 75 6d 65 6e 74 61 74 69 6f 6e 55 74 69 6c 2e [0-32] 20 3d 20 22 43 3a 5c 75 73 65 72 73 5c 50 75 62 6c 69 63 5c 22 20 2b 20 22 [0-4] 2e 6a 70 67 22}  //weight: 1, accuracy: Low
        $x_1_6 = {49 6e 73 74 72 75 6d 65 6e 74 61 74 69 6f 6e 55 74 69 6c 2e [0-32] 20 3d 20 22 68 74 74 70 22}  //weight: 1, accuracy: Low
        $x_1_7 = {49 6e 73 74 72 75 6d 65 6e 74 61 74 69 6f 6e 55 74 69 6c 2e [0-32] 20 3d 20 22 47 45 54 22}  //weight: 1, accuracy: Low
        $x_1_8 = "Len(\"ZZZ\") Then" ascii //weight: 1
        $x_1_9 = {53 68 65 6c 6c 25 20 28 [0-32] 20 2b 20 22 20 22 20 26 20 49 6e 73 74 72 75 6d 65 6e 74 61 74 69 6f 6e 55 74 69 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_PVY_2147774008_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.PVY!MTB"
        threat_id = "2147774008"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://online-docu-sign-st.com/yytr.png" ascii //weight: 1
        $x_1_2 = "C:\\fyjh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_ANNT_2147779800_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.ANNT!MTB"
        threat_id = "2147779800"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 42 41 2e 53 74 72 52 65 76 65 72 73 65 28 22 61 74 68 2e [0-37] 5c 61 74 61 64 6d 61 72 67 6f 72 70 5c 3a 63 20 72 65 72 6f 6c 70 78 65 5c 73 77 6f 64 6e 69 77}  //weight: 1, accuracy: Low
        $x_1_2 = "Public Sub button1_Click()" ascii //weight: 1
        $x_1_3 = "= CreateObject(\"wscript.shell\")" ascii //weight: 1
        $x_1_4 = {2e 65 78 65 63 20 70 28 72 6d 29 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = "= Split(p(frm.rm), \" \")" ascii //weight: 1
        $x_1_6 = "frm.button1_Click" ascii //weight: 1
        $x_1_7 = "<html><body><div id='content'>fTtl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_ANNS_2147779878_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.ANNS!MTB"
        threat_id = "2147779878"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 65 78 70 6c 6f 72 65 72 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c [0-37] 2e 68 74 61 22}  //weight: 1, accuracy: Low
        $x_1_2 = "Public Sub button1_Click()" ascii //weight: 1
        $x_1_3 = {2e 65 78 65 63 20 74 67 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = "frm.button1_Click" ascii //weight: 1
        $x_1_5 = "= Split(frm.tg, \" \")" ascii //weight: 1
        $x_1_6 = "<html><body><div id='content'>fTtl" ascii //weight: 1
        $x_1_7 = "= CreateObject(\"wscript.shell\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_ANNU_2147779925_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.ANNU!MTB"
        threat_id = "2147779925"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub autoopen()" ascii //weight: 1
        $x_1_2 = "Public Sub button1_Click()" ascii //weight: 1
        $x_1_3 = "= Split(frm.tg, \" \")" ascii //weight: 1
        $x_1_4 = {65 78 65 63 20 74 67 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_5 = {66 72 6d 2e 62 75 74 74 6f 6e 31 5f 43 6c 69 63 6b 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_6 = "<html><body><div id='content'>fTtl" ascii //weight: 1
        $x_1_7 = "= CreateObject(\"wscript.shell\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_RPQ_2147805780_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.RPQ!MTB"
        threat_id = "2147805780"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Attribute VB_Name = \"Questa_cartella_di_lavoro\"" ascii //weight: 1
        $x_1_2 = "uu = 3 * yep: y = ((((((((((Run((((((((((\"M\" & \"4\" & \"\"))))))))))))))))))))" ascii //weight: 1
        $x_1_3 = "anndy = Lowe & \"RN\"" ascii //weight: 1
        $x_1_4 = "bolleaan = Split(finesstra, \",\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Gozi_PAAA_2147807748_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Gozi.PAAA!MTB"
        threat_id = "2147807748"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "vb_name=\"foglio1\"" ascii //weight: 1
        $x_1_2 = {66 6f 72 65 61 63 68 64 61 69 6e 62 6f 6c 65 65 61 6e 63 3d 28 62 6e 28 22 3d 22 26 64 61 2c 31 2b 37 29 29 3a [0-63] 28 28 [0-63] 5f 70 61 67 6f 29 29 6e 65 78 74 77}  //weight: 1, accuracy: Low
        $x_1_3 = "((((((((((run((((((((((\"m\"&\"4\"&\"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


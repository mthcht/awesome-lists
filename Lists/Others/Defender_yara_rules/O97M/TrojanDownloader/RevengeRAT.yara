rule TrojanDownloader_O97M_RevengeRAT_SE_2147894670_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/RevengeRAT.SE!MTB"
        threat_id = "2147894670"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "RevengeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 77 77 2e 34 73 79 6e 63 2e 63 6f 6d 2f 77 65 62 2f 64 69 72 65 63 74 44 6f 77 6e 6c 6f 61 64 2f [0-8] 2f 63 6d 6c 55 58 72 45 78 2e}  //weight: 1, accuracy: Low
        $x_1_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 49 6d 61 67 65 6d 53 69 6d 70 6c 65 73 43 44 54 2c 20 [0-100] 20 26 20 22 64 6f 63 75 6d 65 6e 74 2e [0-3] 22 2c 20 30 2c 20 30}  //weight: 1, accuracy: Low
        $x_1_3 = "exe\"\" /c pi" ascii //weight: 1
        $x_1_4 = "ng 127.0.0.1 -n 10" ascii //weight: 1
        $x_1_5 = "> nul & start C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_RevengeRAT_RPI_2147898276_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/RevengeRAT.RPI!MTB"
        threat_id = "2147898276"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "RevengeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://share.zight.com/v1unzned/download/update.vbs?utm_source=viewer" ascii //weight: 1
        $x_1_2 = "https://www.4sync.com/web/directDownload/WtZbKaEl/4PGyG4id.9c4b7b54a07b92c862e81935e0fda974" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_RevengeRAT_RV_2147904749_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/RevengeRAT.RV!MTB"
        threat_id = "2147904749"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "RevengeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ttps://pt.textbin.net/download/itm1dkgz7c');" ascii //weight: 1
        $x_1_2 = {63 61 6c 6c 73 68 65 6c 6c 28 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 2d 63 6f 6d 6d 61 6e 64 22 26 [0-20] 26 22 3b 65 78 69 74 22 2c 76 62 68 69 64 65 29}  //weight: 1, accuracy: Low
        $x_1_3 = "subauto_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_RevengeRAT_NGE_2147911371_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/RevengeRAT.NGE!MTB"
        threat_id = "2147911371"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "RevengeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "'https://pt.textbin.net/download/x7sf6t2dgv' ) ;" ascii //weight: 1
        $x_1_2 = "Call Shell(\"pow\" & \"ers\" & \"hell.exe -command \" & CigvL & \" ; exit \", vbHide)" ascii //weight: 1
        $x_1_3 = "subauto_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_RevengeRAT_RVA_2147915694_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/RevengeRAT.RVA!MTB"
        threat_id = "2147915694"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "RevengeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 22 70 6f 77 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3d 22 65 72 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3d 22 73 68 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3d 22 65 6c 6c 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3d 22 2e 65 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3d 22 78 65 22}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 77 77 77 2e 34 73 79 6e 63 2e 63 6f 6d 2f 77 65 62 2f 64 69 72 65 63 74 64 6f 77 6e 6c 6f 61 64 2f ?? ?? ?? ?? ?? ?? ?? ?? 2f ?? ?? ?? ?? ?? ?? ?? ?? 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 22}  //weight: 1, accuracy: Low
        $x_1_3 = {61 75 74 6f 5f 6f 70 65 6e 28 29 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3d 22 77 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_RevengeRAT_RVA_2147915694_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/RevengeRAT.RVA!MTB"
        threat_id = "2147915694"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "RevengeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 6d 69 63 72 6f 73 6f 66 74 2e 78 6d 6c 68 74 74 70 22 29 64 69 6d 3a 73 65 74 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 61 64 6f 64 62 2e 73 74 72 65 61 6d 22 29 2e 6f 70 65 6e 22 67 65 74 22 2c 22 68 74 74 70 73 3a 2f 2f [0-70] 2f 6f 2f 70 61 79 6c 6f 61 64 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_2 = "=environ(\"appdata\")with.type=1.open.write.responsebody.savetofile&\"/.js" ascii //weight: 1
        $x_1_3 = "shell\"wscript\"&&\"/.js\",vbnormalfocusendsub" ascii //weight: 1
        $x_1_4 = "subauto_open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_RevengeRAT_SIK_2147918043_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/RevengeRAT.SIK!MTB"
        threat_id = "2147918043"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "RevengeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AHQAcABzADoALwAvAGYAaQByAGUAYgBhAHMAZQBzAHQAbwByAGEAZwBlAC4AZwBvAG8AZwBsAGUAYQBwAGkAcwAuAGMAbwBtAC8AdgAwAC8AYgAvAG0AYQBzAHQAZQByAC0AMgA3ADEAYgA4AC4AYQBw" ascii //weight: 1
        $x_1_2 = "AHAAcwBwAG8AdAAuAGMAbwBtAC8AbwAvAE4ATwBWAE8AUgBFAFYARQBSAEcARQBNAC4AagBwAGcAPwBhAGwAdAA9AG0AZQBkAGkAYQAm" ascii //weight: 1
        $x_1_3 = "= Workbooks.Open(FileName:=.FoundFiles(lCount), UpdateLinks:=0)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_RevengeRAT_SS_2147919295_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/RevengeRAT.SS!MTB"
        threat_id = "2147919295"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "RevengeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Set wbResults = Workbooks.Open(FileName:=.FoundFiles(lCount), UpdateLinks:=0)" ascii //weight: 1
        $x_1_2 = {2e 4c 6f 6f 6b 49 6e 20 3d 20 70 63 50 39 4d 73 73 6a 6c 28 [0-31] 28 22 34 46 35 36 37 43 34 42 37 32 38 31 36 46 35 35 36 38 37 37 35 38 35 35 22 29 2c 20 [0-31] 28 22 33 37 22 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {27 4d 73 67 42 6f 78 20 28 70 63 50 39 4d 73 73 6a 6c 28 [0-31] 28 22 35 35 37 32 36 30 37 37 35 38 37 30 34 46 35 30 35 36 37 37 36 31 35 41 37 42 36 42 35 30 36 30 36 44 36 41 35 39 36 43 36 43 35 37 32 37 32 37 32 37 38 31 37 36 34 45 38 30 35 43 36 44 35 41 37 42 35 35 22 29 2c [0-31] 28 22 33 37 22 29 29 29}  //weight: 1, accuracy: Low
        $x_1_4 = "ADoALwAvAGYAaQByAGUAYgBhAHMAZQBzAHQAbwByAGEAZwBlAC4AZwBvAG8AZwBsAGUAYQBwAGkAcwAuAGMAbwBtAC8AdgAwAC8AYgAvAHMAcABhAG0ALQBjADIANwAzAGEALgBhAHAAcABzAHAAbwB0AC4AYwBvAG0A" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


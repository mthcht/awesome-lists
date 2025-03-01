rule TrojanDownloader_O97M_PShell_B_2147725748_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/PShell.B"
        threat_id = "2147725748"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "PShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= Environ$(\"AppData\") & \"\\AdobeAcrobatLicenseVerify.ps1\"" ascii //weight: 1
        $x_1_2 = ".OpenTextFile(qgcLyiCkx, 2, True)" ascii //weight: 1
        $x_1_3 = "= Environ$(\"AppData\") & \"\\AdobeAcrobatLicenseVerify.vbs\"" ascii //weight: 1
        $x_1_4 = "(%WScript.Shell%) : oShell.run %cmd.exe /c Powershell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_PShell_C_2147728668_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/PShell.C"
        threat_id = "2147728668"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "PShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "+ \"=p\" + \"owe\" + \"r;\" + \"he\" + \"ll" ascii //weight: 1
        $x_1_2 = {20 3d 20 22 64 20 2f 56 5e 3a 5e 4f [0-2] 2f 43 22 20 2b 20 22 22 22 22 20 2b 20 22 5e 73 5e 65 5e 74 20}  //weight: 1, accuracy: Low
        $x_1_3 = " = \"d.exe /c p^O^w^e^R^s^H^e^\" + Format(Chr(((" ascii //weight: 1
        $x_1_4 = "//^:\" + \"^\" + \"p\" + \"^t^t\" + \"h@^\" +" ascii //weight: 1
        $x_1_5 = "//^\" + \":^p^\" + \"t^th\"" ascii //weight: 1
        $x_1_6 = " = \"d /V/C\" + \"\"\"\" + \"^s^" ascii //weight: 1
        $x_1_7 = " = \"d \" + CStr(Chr(6 + 7 + 7 + 2 + 25)) + \"V\" + CStr(Chr(" ascii //weight: 1
        $x_1_8 = "/\" + \"/:\" + \"pt^t\" + \"^h^" ascii //weight: 1
        $x_1_9 = ") + \"^se^t\" + \" \" + \"" ascii //weight: 1
        $x_1_10 = {20 3d 20 46 6f 72 6d 61 74 28 43 68 72 28 [0-32] 29 29 20 2b 20 22 6d 64 20 2f 56 [0-32] 22 20 2b 20 46 6f 72 6d 61 74 28 43 68 72 28}  //weight: 1, accuracy: Low
        $x_1_11 = " = \"D  /c \" + \"\"\"^cm^D;  ;  ;  ^/v:^ON^   ;/^c \"\"; ;" ascii //weight: 1
        $x_1_12 = ".DownloadString('http://4host.publicvm.com/api/cscript') | PowersHell" ascii //weight: 1
        $x_1_13 = "\\..\\.\" + \".\\..\\win\" + \"dows\\system\" + \"32\\cmd.exe\" + \" /c %Program\" + \"Data:" ascii //weight: 1
        $x_1_14 = " + \"md /V\" + \"^:/\" + Chr(" ascii //weight: 1
        $x_1_15 = {53 68 65 6c 6c 20 46 6f 72 6d 61 74 28 [0-32] 29 20 2b 20 46 6f 72 6d 61 74 28}  //weight: 1, accuracy: Low
        $x_1_16 = {20 2b 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 52 75 6e 28 [0-32] 20 2b 20 43 68 72 28}  //weight: 1, accuracy: Low
        $x_1_17 = {56 42 41 2e 53 68 65 6c 6c 20 22 22 20 2b 20 [0-48] 20 2b 20 43 56 61 72 28 22 43 22 29 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_O97M_PShell_D_2147730590_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/PShell.D"
        threat_id = "2147730590"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "PShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " = \"^" ascii //weight: 1
        $x_1_2 = "\" + \"^" ascii //weight: 1
        $x_1_3 = "^\" + \"" ascii //weight: 1
        $x_1_4 = "Resume " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_PShell_F_2147730885_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/PShell.F"
        threat_id = "2147730885"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "PShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 43 6c 6f 73 65 28 29 0d 0a 45 6e 64 5f 5f 0d 0a 45 6e 64 20 53 75 62 [0-8] 50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 [0-8] 57 69 74 68 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 0d 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 6f 6f 6b 6d 61 72 6b 73 28 22 62 5f 22 29 2e 52 61 6e 67 65 2e 53 65 6c 65 63 74 0d 0a 20 20 20 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 6f 6f 6b 6d 61 72 6b 73 28 22 62 5f 22 29 2e 52 61 6e 67 65 2e 46 6f 6e 74 2e 48 69 64 64 65 6e 20 3d 20 54 72 75 65 0d 0a 20 20 20 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 65 6c 65 63 74 69 6f 6e 2e 45 6e 64 4f 66 0d 0a 20 20 20 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 61 76 65 0d 0a 45 6e 64 20 53 75 62 0d 0a}  //weight: 1, accuracy: High
        $x_1_3 = {2e 52 75 6e 20 22 43 6d 64 20 2f 43 [0-3] 22 20 2b 20 43 68 72 28 33 34 29 20 2b 20 22 [0-3] 45 63 68 6f [0-3] 49 45 58 20}  //weight: 1, accuracy: Low
        $x_1_4 = "| pOwErSheLl " ascii //weight: 1
        $x_1_5 = {2b 20 43 68 72 28 33 34 29 2c 20 30 2c 20 46 61 6c 73 65 [0-6] 45 6e 64 20 57 69 74 68 [0-6] 0d 0a 53 74 61 72 74 5f 5f 0d 0a [0-4] 45 6e 64 20 53 75 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_PShell_G_2147741123_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/PShell.G"
        threat_id = "2147741123"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "PShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"Wscript.Shell\")" ascii //weight: 1
        $x_1_2 = ".RegWrite \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updat\", \"wscript" ascii //weight: 1
        $x_1_3 = {45 6e 76 69 72 6f 6e 24 28 22 55 73 65 72 70 72 6f 66 69 6c 65 22 29 20 26 20 22 [0-32] 5c 53 69 6c 65 6e 74 2e 76 62 73 22 2c 20 22 52 45 47 5f 53 5a 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_PShell_H_2147741167_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/PShell.H"
        threat_id = "2147741167"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "PShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 61 6c 6c 20 [0-32] 28 22 68 74 74 70 [0-2] 3a 2f 2f [0-48] 2f [0-16] 2e 6a 70 67 22 2c 20 45 6e 76 69 72 6f 6e 28 22 41 70 70 44 61 74 61 22 29 20 26 20 22 5c [0-16] 2e 65 78 65 22 29}  //weight: 2, accuracy: Low
        $x_1_2 = ".SaveToFile(SDE, 2)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_PShell_P_2147750310_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/PShell.P!MSR"
        threat_id = "2147750310"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "PShell"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 65 72 74 75 74 69 6c 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 68 74 74 70 [0-2] 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f [0-16] 2f [0-37] 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c [0-32] 2e 65 6e 63}  //weight: 1, accuracy: Low
        $x_1_2 = {63 65 72 74 75 74 69 6c 20 2d 66 20 2d 64 65 63 6f 64 65 20 [0-5] 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c [0-32] 2e 65 6e 63 20 [0-5] 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c [0-32] 2e 70 73 31}  //weight: 1, accuracy: Low
        $x_1_3 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 65 78 65 63 75 74 69 6f 6e 70 6f 6c 69 63 79 20 62 79 70 61 73 73 20 2d 63 20 69 65 78 20 [0-5] 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c [0-32] 2e 70 73 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


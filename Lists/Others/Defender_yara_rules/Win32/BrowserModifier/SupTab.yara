rule BrowserModifier_Win32_SupTab_214126_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/SupTab"
        threat_id = "214126"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "SupTab"
        severity = "64"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Oursurfing.exe -silence -ptid=" ascii //weight: 1
        $x_1_2 = "&bundle=Component&product=Oursurfing&status=" ascii //weight: 1
        $x_1_3 = "\\luckysearchesSoftware\\luckysearcheshp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule BrowserModifier_Win32_SupTab_214126_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/SupTab"
        threat_id = "214126"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "SupTab"
        severity = "64"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c 62 69 6e 5c 70 78 64 6c 2e 70 64 62 00}  //weight: 2, accuracy: High
        $x_2_2 = "{9CEE239D-2901-4D60-AE9E-25CDA88D47E2}" ascii //weight: 2
        $x_1_3 = {25 73 2f 25 73 2f 25 73 3f 61 63 74 69 6f 6e 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {25 73 20 2d 70 74 69 64 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {65 55 70 67 72 61 64 65 5c 65 75 70 67 72 61 64 65 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_SupTab_214126_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/SupTab"
        threat_id = "214126"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "SupTab"
        severity = "64"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-enablebho -bhoid={" ascii //weight: 1
        $x_1_2 = "\\MiuiTab" ascii //weight: 1
        $x_1_3 = "\\ProtectService.exe" ascii //weight: 1
        $x_1_4 = "sc delete IePluginServices" ascii //weight: 1
        $x_1_5 = "\\SupTab\\SupTab.dll" ascii //weight: 1
        $x_1_6 = "\\MiniLite" ascii //weight: 1
        $x_1_7 = "\\searchProvider.xml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule BrowserModifier_Win32_SupTab_214126_3
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/SupTab"
        threat_id = "214126"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "SupTab"
        severity = "64"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {53 4f 46 54 57 41 52 45 5c 57 64 73 4d 61 6e 50 72 6f 00}  //weight: 2, accuracy: High
        $x_2_2 = "{262E20B8-6E20-4CEF-B1FD-D022AB1085F5}" ascii //weight: 2
        $x_1_3 = {4d 61 6e 67 65 72 50 72 6f 74 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {57 64 73 4d 61 6e 50 72 6f 00}  //weight: 1, accuracy: High
        $x_1_5 = {6d 69 6e 69 5f 7a 69 70 00}  //weight: 1, accuracy: High
        $x_2_6 = "update0=ref,%s&update1=nation,%s&update2=language,%s" ascii //weight: 2
        $x_2_7 = "\\TMain\\Release\\SvrUpdater.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_SupTab_214126_4
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/SupTab"
        threat_id = "214126"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "SupTab"
        severity = "64"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c 54 4d 61 69 6e 5c 52 65 6c 65 61 73 65 5c 54 53 76 72 2e 70 64 62 00}  //weight: 2, accuracy: High
        $x_1_2 = {54 00 53 00 76 00 72 00 2e 00 63 00 66 00 69 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 00 56 00 52 00 3a 00 20 00 49 00 20 00 77 00 69 00 6c 00 6c 00 20 00 65 00 78 00 69 00 74 00 2e 00 2e 00 2e 00 2e 00 2e 00 0a 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "Manages network policy and network policy notification delivery for TSv.com." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_SupTab_214126_5
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/SupTab"
        threat_id = "214126"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "SupTab"
        severity = "64"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/sof-installer/%s?action1=xa.geoip&action2=visit" ascii //weight: 2
        $x_2_2 = "\\InstallerMainV6_Yrrehs\\Release\\Main.pdb" ascii //weight: 2
        $x_2_3 = "Main_t00ls_Yrrehs" ascii //weight: 2
        $x_2_4 = "/%s?action=%s.dlzip" ascii //weight: 2
        $x_1_5 = {5c 49 5c 63 6f 6e 66 00}  //weight: 1, accuracy: High
        $x_1_6 = ".%s.finish" ascii //weight: 1
        $x_2_7 = {5c 49 5c 74 6d 70 00 00 49 49 2e 7a 69 70 00}  //weight: 2, accuracy: High
        $x_1_8 = {25 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 25 00 30 00 32 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_2_9 = {49 00 49 00 2e 00 7a 00 69 00 70 00 00 00 00 00 5c 00 49 00 00 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_SupTab_214126_6
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/SupTab"
        threat_id = "214126"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "SupTab"
        severity = "64"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\SearchProtect\\Bin\\Release\\CmdShell.pdb" ascii //weight: 2
        $x_2_2 = "1F4C6304-865F-41EA-B18C-DB10B5F77DF5" ascii //weight: 2
        $x_2_3 = "5F26509F-29FE-4598-8800-FA22CE9CC17F" ascii //weight: 2
        $x_2_4 = "HPNotify.exe -run -ptid=%s" ascii //weight: 2
        $x_1_5 = {25 73 63 6f 6e 66 00}  //weight: 1, accuracy: High
        $x_2_6 = "\\SearchProtect\\bin\\Release\\HPNotify.pdb" ascii //weight: 2
        $x_2_7 = "&ts=%d&from=xtab&uid=%s" ascii //weight: 2
        $x_1_8 = "/searchprotect/%s?action" ascii //weight: 1
        $x_1_9 = {53 55 50 44 75 69 57 69 6e 64 6f 77 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_SupTab_214126_7
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/SupTab"
        threat_id = "214126"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "SupTab"
        severity = "64"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%s%s?action=browser.%s.prevent.homepage.%s" ascii //weight: 2
        $x_2_2 = "\\Release\\SFKEX.pdb" ascii //weight: 2
        $x_2_3 = "\\x64\\Release\\SFKEX64.pdb" ascii //weight: 2
        $x_1_4 = {59 00 72 00 72 00 65 00 68 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {59 00 72 00 72 00 00 00 65 00 68 00 73 00 00 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "t00ls_Y[S" ascii //weight: 1
        $x_2_7 = "t00l_Yrrehs_EX_" wide //weight: 2
        $x_1_8 = "/logic/z.php" ascii //weight: 1
        $x_1_9 = "xa.xingcloud.com/v4/sof-everything/" ascii //weight: 1
        $x_1_10 = {78 69 6e 67 63 6c 00 00 6f 75 64 2e 63 6f 6d 2f 76 34 2f 00 73 6f 66 2d 65 76 65 72 79 00 00 00 74 68 69 6e 67 2f}  //weight: 1, accuracy: High
        $x_1_11 = {5c 53 46 4b 45 58 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_SupTab_214126_8
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/SupTab"
        threat_id = "214126"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "SupTab"
        severity = "64"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 5f 53 65 74 44 65 66 61 75 6c 74 53 65 61 72 63 68 00}  //weight: 1, accuracy: High
        $x_1_2 = {65 5f 53 65 74 48 6f 6d 65 50 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\SearchProtect\\Bin\\Release\\BrowerWatch" ascii //weight: 1
        $x_1_4 = "I will exit watching thread." wide //weight: 1
        $x_2_5 = "\\SearchProtect\\Bin\\Release\\IeWatchDog.pdb" ascii //weight: 2
        $x_1_6 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 53 00 65 00 61 00 72 00 63 00 68 00 53 00 63 00 6f 00 70 00 65 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = "\\bin\\BrowserAction_MD.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_SupTab_214126_9
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/SupTab"
        threat_id = "214126"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "SupTab"
        severity = "64"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/searchprotect/up?ptid=%s&sid=%s&ln=%s_%s&ver=%s&uid=%s&dp=%s" ascii //weight: 2
        $x_2_2 = "2EFFE99D-743D-44D0-BBF2-F9DDDEA2F92D" ascii //weight: 2
        $x_2_3 = "\\SearchProtect\\Bin\\Release\\ProtectService.pdb" ascii //weight: 2
        $x_1_4 = "/searchprotect/%s?action" ascii //weight: 1
        $x_1_5 = {63 6d 64 73 68 65 6c 6c 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {49 48 50 72 6f 74 65 63 74 55 70 44 61 74 65 00}  //weight: 1, accuracy: High
        $x_2_7 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 49 00 48 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 00 00}  //weight: 2, accuracy: High
        $x_2_8 = {49 00 48 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 50 00 6c 00 75 00 67 00 69 00 6e 00 00 00}  //weight: 2, accuracy: High
        $x_2_9 = {53 55 68 51 63 6d 39 30 5a 57 4e 30 55 47 78 31 5a 32 6c 75 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_SupTab_214126_10
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/SupTab"
        threat_id = "214126"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "SupTab"
        severity = "64"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "/sof-installer/%s?action=%s.uninstall.%s" ascii //weight: 2
        $x_1_2 = {55 6e 69 6e 73 74 61 6c 6c 4d 61 6e 61 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 55 50 44 75 69 57 69 6e 64 6f 77 00}  //weight: 1, accuracy: High
        $x_1_4 = " will be removed, are you sure to continue?" ascii //weight: 1
        $x_1_5 = {5c 53 75 70 54 61 62 5c 00}  //weight: 1, accuracy: High
        $x_2_6 = {75 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 [0-2] 44 00 6c 00 67 00 32 00 2e 00 78 00 6d 00 6c 00 00}  //weight: 2, accuracy: Low
        $x_2_7 = {75 6e 69 6e 73 74 61 6c 6c [0-2] 44 6c 67 32 2e 78 6d 6c 00}  //weight: 2, accuracy: Low
        $x_2_8 = "<Option name=\"HpProtect\"" ascii //weight: 2
        $x_1_9 = "\\MiniLite" ascii //weight: 1
        $x_1_10 = "Windows Protect Manager" ascii //weight: 1
        $x_2_11 = "\\extensions\\defsearchp@gmail.com\\install.rdf" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_SupTab_214126_11
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/SupTab"
        threat_id = "214126"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "SupTab"
        severity = "64"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\SupNewTab\\bin\\SupTab.pdb" ascii //weight: 2
        $x_2_2 = "2023ECEC-E06A-4372-A1C7-0B49F9E0FFF0" ascii //weight: 2
        $x_2_3 = "BFAC251F-FE56-45F9-B134-2CD7DCBF8EE0" ascii //weight: 2
        $x_2_4 = "update0=ref,%s&update1=nation,%s&update2=language,%s" ascii //weight: 2
        $x_1_5 = "/sof-ient/%s?action" ascii //weight: 1
        $x_1_6 = {6e 6f 20 6c 6f 61 64 20 75 72 6c 6d 6f 6e 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_7 = {69 6e 73 74 61 6c 6c 5f 69 65 00}  //weight: 1, accuracy: High
        $x_2_8 = "t00ls_Y[S" ascii //weight: 2
        $x_2_9 = {74 30 30 6c 00 48 4f 4d}  //weight: 2, accuracy: High
        $x_2_10 = "xa.xingcloud.com/v4/sof-everything/" ascii //weight: 2
        $x_2_11 = "\\SSFK\\Release\\SSFK.pdb" ascii //weight: 2
        $x_2_12 = "\\supsoft\\WPM2.0\\Release\\ReportDll.pdb" ascii //weight: 2
        $x_1_13 = "/sof-everything/%s?action" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_SupTab_214126_12
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/SupTab"
        threat_id = "214126"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "SupTab"
        severity = "64"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Everything.exe" wide //weight: 1
        $x_1_2 = "TheradTask::Stop:%d:%d:%d" wide //weight: 1
        $x_1_3 = "http://www.thefacebooksinfo.com/Public/softs/freefinder/FreeFinderResourcesNew.zip" wide //weight: 1
        $x_1_4 = "\\net_search\\" wide //weight: 1
        $x_1_5 = "/everything/up?ptid=%s&sid=%s&ln=%s_%s&ver=%s&uid=%s" wide //weight: 1
        $x_1_6 = "SFKEX64.exe" wide //weight: 1
        $x_1_7 = "SFKEX.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_SupTab_214126_13
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/SupTab"
        threat_id = "214126"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "SupTab"
        severity = "64"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 73 69 6c 65 6e 63 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {2d 70 74 69 64 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_3 = "/sof-installer/%s?action=%s" ascii //weight: 1
        $x_1_4 = {00 5c 63 6f 6e 66 00}  //weight: 1, accuracy: High
        $x_2_5 = "-force  -type=%d -innerptid=%s -mver=%s  %s" ascii //weight: 2
        $x_2_6 = "-force  -type=%s -innerptid=%s -mver=%s  %s" ascii //weight: 2
        $x_1_7 = "FBFDE863-3C17-4B82-A5D1-9B8ED5BE6B40.tmp" ascii //weight: 1
        $x_1_8 = {2d 00 66 00 6f 00 72 00 63 00 65 00 20 00 2d 00 74 00 79 00 70 00 65 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_2_9 = "?action=%s.dlzip1.%s.finish,%d" ascii //weight: 2
        $x_2_10 = "160DD503-E139-4E78-AB29-79A839E404BE" ascii //weight: 2
        $x_2_11 = "-innerptid=%s  -mver=%s" ascii //weight: 2
        $x_1_12 = {5a 65 72 6f 2d 74 6d 70 00}  //weight: 1, accuracy: High
        $x_3_13 = {8a 0c 37 8a d1 80 e2 01 c0 e2 02 8a c1 24 02 02 d0 c0 e2 02 8a c1 24 04 02 d0 c0 e2 02 8a c1 c0 f8 06 24 01 02 d0 8a c1 c0 f8 04 24 02 02 d0 8a c1 c0 f8 02 24 04 02 d0 8a c1 24 80 02 d0 80 e1 08 02 d1 88 14 37}  //weight: 3, accuracy: High
        $x_2_14 = {2f 00 25 00 73 00 2f 00 31 00 00 00 2f 00 25 00 73 00 2f 00 32 00 00 00}  //weight: 2, accuracy: High
        $x_2_15 = {8b d7 83 e2 03 c1 e2 06 83 e0 3f 0b c2 8b 55 ?? 8a 92 ?? ?? ?? ?? 8b d9 c1 fb 04 80 e3 03 c0 e2 02 0a da 8b 55 ?? 88 1c 16 8b df c1 fb 02 80 e3 0f c0 e1 04 0a d9}  //weight: 2, accuracy: Low
        $x_2_16 = {2f 25 73 2f 31 00 00 00 2f 25 73 2f 32 00}  //weight: 2, accuracy: High
        $x_1_17 = {31 00 32 00 33 00 62 00 2e 00 7a 00 69 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_18 = {34 00 35 00 36 00 62 00 2e 00 7a 00 69 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_2_19 = "849E93D6-4D33-4AAD-A4FD-42A14F13FA00" ascii //weight: 2
        $x_2_20 = {55 70 67 72 61 64 65 20 57 69 7a 61 72 20 64 00}  //weight: 2, accuracy: High
        $x_1_21 = {51 44 6f 36 48 52 46 44 46 30 4d 68 51 32 64 54 00}  //weight: 1, accuracy: High
        $x_2_22 = {8a 55 08 53 8a da 80 e3 01 c0 e3 02 8a c2 24 02 02 d8 c0 e3 02 8a c2 24 04 02 d8 8a c2 c0 f8 06 24 01 c0 e3 02 02 d8 8a c2}  //weight: 2, accuracy: High
        $x_2_23 = {0f b6 04 1e 8b 4d ?? 50 e8 ?? ?? ?? ?? 88 04 1e 46 3b f7 7c eb}  //weight: 2, accuracy: Low
        $x_1_24 = {8b f0 83 7e 14 10 72 02 8b 36 85 f6 74 ?? 68 04 01 00 00 8d 44 24 48 50 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_25 = {53 74 61 72 74 41 73 46 72 61 6d 65 50 72 6f 63 65 73 73 00}  //weight: 1, accuracy: High
        $x_2_26 = {2e 2e 5c 44 61 74 61 42 61 73 65 00 44 6f 57 6f 72 6b 00}  //weight: 2, accuracy: High
        $x_2_27 = {04 06 32 d2 32 db 80 c7 04 83 c7 04 ff 4d ?? 88 45 ?? 0f 85 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_2_28 = {75 6e 69 6e 73 74 61 6c 6c 44 6c 67 32 2e 78 6d 6c 00}  //weight: 2, accuracy: High
        $x_2_29 = "LWZvcmNlICAtdHlwZT0xIC1pbm5lcnB0aWQ9" ascii //weight: 2
        $x_2_30 = {2e 2e 5c 74 65 73 74 00 44 6f 57 6f 72 6b 00}  //weight: 2, accuracy: High
        $x_2_31 = {2e 2e 5c 6d 61 69 6e 75 70 00 00 00 44 6f 57 6f 72 6b 00}  //weight: 2, accuracy: High
        $x_1_32 = {8b 41 10 0f b7 50 06 6b d2 28 03 50 54 52 6a 00 ff 71 08 e8}  //weight: 1, accuracy: High
        $x_2_33 = {49 20 73 20 74 20 68 65 20 4c 61 74 65 73 74 20 56 65 72 73 69 6f 6e 21 00}  //weight: 2, accuracy: High
        $x_2_34 = {2e 2e 5c 44 61 74 61 42 61 73 65 00 44 6f 00 00 57 6f 00 00 72 6b 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}


rule Misleading_Win32_Winfixer_199425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Winfixer"
        threat_id = "199425"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Winfixer"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://updates.winsoftware.com/" ascii //weight: 1
        $x_1_2 = "err.log" ascii //weight: 1
        $x_1_3 = "&pcid=" ascii //weight: 1
        $x_1_4 = "/ping.php" ascii //weight: 1
        $x_1_5 = "up.dat" ascii //weight: 1
        $x_1_6 = "deld.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Misleading_Win32_Winfixer_199425_1
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Winfixer"
        threat_id = "199425"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Winfixer"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "available for download on remote server" ascii //weight: 1
        $x_1_2 = "already installed on local computer" ascii //weight: 1
        $x_1_3 = "Connecting to server..." ascii //weight: 1
        $x_1_4 = "updater.dat" ascii //weight: 1
        $x_1_5 = "update.log" ascii //weight: 1
        $x_1_6 = "DriveCleanerUpdaterTerminationEvent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Misleading_Win32_Winfixer_199425_2
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Winfixer"
        threat_id = "199425"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Winfixer"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Deus Cleaner" ascii //weight: 1
        $x_1_2 = "inaccuracy_total..." ascii //weight: 1
        $x_1_3 = "DCUpdate.exe /R" ascii //weight: 1
        $x_1_4 = "DEUS_CLEANER_APP_CLOSE" ascii //weight: 1
        $x_1_5 = "DEUS_CLEANER_SD" ascii //weight: 1
        $x_1_6 = "*DC.lng" ascii //weight: 1
        $x_1_7 = "Deus Software" wide //weight: 1
        $x_1_8 = "Deus Cleaner" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Misleading_Win32_Winfixer_199425_3
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Winfixer"
        threat_id = "199425"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Winfixer"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mailto" ascii //weight: 1
        $x_1_2 = "_sourcevss\\Products\\prototypes\\AdvancedCleaner\\ADCcw\\ADCcw\\Release\\ADCcw.pdb" ascii //weight: 1
        $x_1_3 = "advancedcleaner.com" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Misleading_Win32_Winfixer_199425_4
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Winfixer"
        threat_id = "199425"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Winfixer"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 6f 77 6e 6c 6f 61 64 65 64 00 00 46 69 6c 65 4b 65 79 50 61 69 64 00 43 53 49 44 4c 5f 54 45 4d 50 4c 41 54 45 53}  //weight: 1, accuracy: High
        $x_1_2 = "/pn=%s /url=%s" ascii //weight: 1
        $x_1_3 = "actn_abbr_v2" ascii //weight: 1
        $x_1_4 = {47 6c 6f 62 61 6c 00 00 2e 64 61 74 00 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e}  //weight: 1, accuracy: High
        $x_1_5 = {53 61 6c 65 73 4d 6f 6e 69 74 6f 72 00 00 00 00 4e 65 74 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_6 = "profile\\cookies4.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Misleading_Win32_Winfixer_199425_5
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Winfixer"
        threat_id = "199425"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Winfixer"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_2 = "InternetGetCookieA" ascii //weight: 10
        $x_10_3 = "RegSetValueExA" ascii //weight: 10
        $x_10_4 = "GetStartupInfoA" ascii //weight: 10
        $x_1_5 = "http://advancedcleaner.com" wide //weight: 1
        $x_1_6 = "UADC = 1; expires =   GMT" ascii //weight: 1
        $x_1_7 = "prototypes\\advancedcleaner" ascii //weight: 1
        $x_1_8 = "advancedcleaner.com|UADC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Misleading_Win32_Winfixer_199425_6
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Winfixer"
        threat_id = "199425"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Winfixer"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PCPrivacyTool\\GDC.exe" wide //weight: 1
        $x_1_2 = "SpyGuardPro\\Dat\\bnlink.dat" wide //weight: 1
        $x_1_3 = "SpyGuardPro\\pgs.exe" wide //weight: 1
        $x_1_4 = "http://clean.systemerrorfixer.com/MTg1MzE=/2/" wide //weight: 1
        $x_1_5 = "Your System has much of errors! Please click on the button below to download and install the software to Fix Them!" wide //weight: 1
        $x_1_6 = "http://protect.spyguardpro.com/MTkyNDE=/2/" ascii //weight: 1
        $x_1_7 = "Your system is infected with spyware, protection level is criticaly low." ascii //weight: 1
        $x_1_8 = "http://protect.advancedcleaner.com/MjY5Mw==/2/" ascii //weight: 1
        $x_1_9 = "ttp://p/(ct.a7p2" ascii //weight: 1
        $x_1_10 = "Y5Mw==/2/830/ax=" ascii //weight: 1
        $x_1_11 = "!.lnk+%WBn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Misleading_Win32_Winfixer_199425_7
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Winfixer"
        threat_id = "199425"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Winfixer"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 73 74 6f 70 00 00 00 2d 73 74 61 72 74}  //weight: 1, accuracy: High
        $x_1_2 = "_deleted_" ascii //weight: 1
        $x_1_3 = "\"%s\" -start" ascii //weight: 1
        $x_1_4 = {44 65 6c 65 74 65 00 00 4e 6f 52 65 6d 6f 76 65 00 00 00 00 46 6f 72 63 65 52 65 6d 6f 76 65}  //weight: 1, accuracy: High
        $x_1_5 = "OpenProcess" ascii //weight: 1
        $x_1_6 = "Process32Next" ascii //weight: 1
        $x_1_7 = {8b 44 24 04 83 f8 07 77 20 ff 24 85 c0 12 40 00 66 b8 15 00 c3 66 b8 46 00 c3 66 b8 50 00 c3 66 b8 bb 01 c3 66 b8 38 04 c3 66 33 c0 c3}  //weight: 1, accuracy: High
        $x_1_8 = {68 84 00 00 00 50 8d 4c 24 20 e8 ?? ?? ?? ff 57 68 85 00 00 00 e8 ?? ?? ?? ff 83 c4 08 3b c7 74 0f 68 85 00 00 00 50 8d 4c 24 2c e8 ?? ?? ?? ff 57 68 82 00 00 00 e8 ?? ?? ?? ff 83 c4 08 3b c7 74 0f 68 82 00 00 00 50 8d 4c 24 14 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Misleading_Win32_Winfixer_199425_8
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Winfixer"
        threat_id = "199425"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Winfixer"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 86 00 04 00 00 33 db 8a 1f 8b d0 c1 ea 18 c1 e0 08 33 d3 81 e2 ff 00 00 00 33 04 96 47 49 89 86 00 04 00 00 75 d9}  //weight: 1, accuracy: High
        $x_1_2 = {8b 86 00 04 00 00 0f b6 1f 8b d0 c1 ea 18 33 d3 81 e2 ff 00 00 00 c1 e0 08 33 04 96 47 49 89 86 00 04 00 00 75 da}  //weight: 1, accuracy: High
        $x_1_3 = {6a 04 68 de 00 00 00 68 a1 01 00 00 68 8a 00 00 00 6a 0e}  //weight: 1, accuracy: High
        $x_1_4 = {2f 00 61 00 64 00 2f 00 62 00 6b 00 2f 00 37 00 34 00 31 00 32 00 2d 00 33 00 39 00 36 00 31 00 34 00 2d 00 32 00 30 00 35 00 34 00 2d 00 31 00 30 00 3f 00 73 00 65 00 74 00 75 00 70 00 3d 00 31 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {26 00 6d 00 70 00 75 00 69 00 64 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {49 00 4d 00 20 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 5c 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 34 00 2e 00 64 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


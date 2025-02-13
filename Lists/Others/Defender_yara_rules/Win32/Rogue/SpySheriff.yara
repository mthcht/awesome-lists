rule Rogue_Win32_SpySheriff_15963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "download.PestCapture.com" ascii //weight: 1
        $x_1_2 = "/pcdownload.php?&" ascii //weight: 1
        $x_1_3 = "PestCapture.exe" ascii //weight: 1
        $x_2_4 = "69.50.175.1" ascii //weight: 2
        $x_1_5 = "SOFTWARE\\PestCaptureSetup" ascii //weight: 1
        $x_1_6 = "PestCapture 3.2 Setup" ascii //weight: 1
        $x_1_7 = "Are you sure you wish to cancel setup?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_SpySheriff_15963_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Host: download.bravesentry.com" ascii //weight: 1
        $x_1_2 = "/download.php?&" ascii //weight: 1
        $x_1_3 = "BraveSentry.exe" ascii //weight: 1
        $x_2_4 = "69.50.175.181" ascii //weight: 2
        $x_1_5 = "SOFTWARE\\BraveSentrySetup" ascii //weight: 1
        $x_1_6 = "BraveSentry 2.0 Setup" ascii //weight: 1
        $x_1_7 = "Are you sure you wish to cancel setup?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_SpySheriff_15963_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Host: download.spy-shredder.com" ascii //weight: 1
        $x_1_2 = "/ssdownload.php?&" ascii //weight: 1
        $x_1_3 = "SpyShredder.exe" ascii //weight: 1
        $x_2_4 = "69.50.175.180" ascii //weight: 2
        $x_1_5 = "SOFTWARE\\SpyShredderSetup" ascii //weight: 1
        $x_1_6 = "SpyShredder 2.0 Setup" ascii //weight: 1
        $x_1_7 = "Are you sure you wish to cancel setup?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_SpySheriff_15963_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Host: download.MalwareAlarm.com" ascii //weight: 1
        $x_1_2 = "/madownload.php?&" ascii //weight: 1
        $x_1_3 = "MalwareAlarm.exe" ascii //weight: 1
        $x_2_4 = "69.50.175.180" ascii //weight: 2
        $x_1_5 = "SOFTWARE\\MalwareAlarmSetup" ascii //weight: 1
        $x_1_6 = "MalwareAlarm 2.0 Setup" ascii //weight: 1
        $x_1_7 = "Are you sure you wish to cancel setup?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_SpySheriff_15963_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "download.Malware-Stopper.com" ascii //weight: 1
        $x_1_2 = "/mtdownload.php?&" ascii //weight: 1
        $x_1_3 = "MalwareStopper.exe" ascii //weight: 1
        $x_2_4 = "69.50.175.1" ascii //weight: 2
        $x_1_5 = "SOFTWARE\\MalwareStopperSetup" ascii //weight: 1
        $x_1_6 = "MalwareStopper 3.2 Setup" ascii //weight: 1
        $x_1_7 = "Are you sure you wish to cancel setup?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_SpySheriff_15963_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\ASProtect\\SpecData" ascii //weight: 1
        $x_1_2 = "\\\\.\\NTICE" ascii //weight: 1
        $x_1_3 = "HELO User.With.Error" ascii //weight: 1
        $x_1_4 = "processorArchitecture=\"x86\"" ascii //weight: 1
        $x_1_5 = "name=\"SN.SpywareNoUninstall\"" ascii //weight: 1
        $x_1_6 = "type=\"win32\"" ascii //weight: 1
        $x_1_7 = "Spyware scanner and remover. Uninstall.</description>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_SpySheriff_15963_6
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\AnvTrgr.exe" ascii //weight: 1
        $x_1_2 = "Software\\AnvTrgrsoft" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\AnvTrgrsoft" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AnvTrgrsoft" ascii //weight: 1
        $x_1_5 = "http://www.virtrigger.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_SpySheriff_15963_7
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "download.AntiSpyShield.com" ascii //weight: 1
        $x_1_2 = "/addownload.php?&" ascii //weight: 1
        $x_1_3 = "AntiSpywareShield.exe" ascii //weight: 1
        $x_2_4 = "69.50.167.26" ascii //weight: 2
        $x_1_5 = "AntiSpywareShield End User License Agreement" ascii //weight: 1
        $x_1_6 = "AntiSpywareShield Setup" ascii //weight: 1
        $x_1_7 = "Are you sure you wish to cancel setup?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_SpySheriff_15963_8
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "76"
        strings_accuracy = "High"
    strings:
        $x_35_1 = "Software\\AnvTrgrsoft" ascii //weight: 35
        $x_35_2 = "hui22" ascii //weight: 35
        $x_5_3 = "segpay.com" ascii //weight: 5
        $x_5_4 = "virustrigger2009.com" ascii //weight: 5
        $x_5_5 = "virus-triggers.com" ascii //weight: 5
        $x_5_6 = "systemtrigger.com" ascii //weight: 5
        $x_5_7 = "virus-trigger.com" ascii //weight: 5
        $x_5_8 = "virtrigger.com" ascii //weight: 5
        $x_1_9 = "http://%s/sync.php" ascii //weight: 1
        $x_1_10 = "http://%s/features.php" ascii //weight: 1
        $x_1_11 = "http://%s/support.php" ascii //weight: 1
        $x_1_12 = "http://%s/buy_online.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_35_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_35_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_SpySheriff_15963_9
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Program Files\\SpyShredder\\SpyShredder.exe" ascii //weight: 2
        $x_2_2 = {59 59 59 59 59 59 20 48 54 54 50 2f 31 2e 30 0d 0a 48 6f 73 74 3a 20 64 6f 77 6e 6c 6f 61 64 2e 73 70 79 2d 73 68 72 65 64 64 65 72 2e 63 6f 6d}  //weight: 2, accuracy: High
        $x_2_3 = {50 72 6f 67 72 61 6d 20 46 69 00 00 00 68 72 65 64 64 65 72 5c 53 00 00 00 65 64 64 65 72 2e 65 78 65 00 00 00 57 69 6e 64 6f 77 73 20 75 70 64 61 74 65 20 6c 6f 61 64 65 72 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e}  //weight: 2, accuracy: High
        $x_2_4 = {36 39 2e 35 30 2e 31 37 35 2e 31 38 30 00 00 00 47 45 54 20 68 74 74 70 3a 2f 2f 25 73 2f 61 73 67 68 66 64 2e 70 68 70 3f 26 26 75 3d 25 75 26 70 3d 25 75 26 6c 61 6e 67}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_SpySheriff_15963_10
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "82"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "GetLastActivePopup" ascii //weight: 10
        $x_10_2 = "NOTICE TO USER:  PLEASE READ THIS CONTRACT CAREFULLY" ascii //weight: 10
        $x_10_3 = "C:\\Program Files\\%s\\%s.lic" ascii //weight: 10
        $x_10_4 = "C:\\Program Files\\%s\\%s.exe" ascii //weight: 10
        $x_10_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii //weight: 10
        $x_10_6 = "ProxyEnable" ascii //weight: 10
        $x_10_7 = "Internet connection is unavailable. Try again?" ascii //weight: 10
        $x_10_8 = "CreateDirectoryA" ascii //weight: 10
        $x_1_9 = "&advid=" ascii //weight: 1
        $x_1_10 = "&u=%u&p=%u %s%sHo" ascii //weight: 1
        $x_1_11 = "%sload.%s.com" ascii //weight: 1
        $x_1_12 = "st: down" ascii //weight: 1
        $x_1_13 = "%sCache%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_SpySheriff_15963_11
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MalwareBell.com" ascii //weight: 1
        $x_1_2 = "Your computer is still infected! Are you sure to exit now?" ascii //weight: 1
        $x_1_3 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_SpySheriff_15963_12
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {45 6e 64 20 55 73 65 72 20 4c 69 63 65 6e 73 65 20 41 67 72 65 65 6d 65 6e 74 0d 0a 0d 0a 4e 4f 54 49 43 45 20 54 4f 20 55 53 45 52 3a 20 20 50 4c 45 41 53 45 20 52 45 41 44 20 54 48 49 53 20 43 4f 4e 54 52 41 43 54 20 43 41 52 45 46 55 4c 4c 59 2e}  //weight: 10, accuracy: High
        $x_10_2 = "Please refer to the " ascii //weight: 10
        $x_10_3 = "Are you sure you wish to cancel setup?" ascii //weight: 10
        $x_1_4 = {36 39 2e 35 30 2e 31 [0-5] 00 00 00 00 47 45 54 20 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_SpySheriff_15963_13
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Scan complete. Idle." ascii //weight: 1
        $x_1_2 = "firstrun.php?i=pc&advid=%u HTTP/1.0" ascii //weight: 1
        $x_1_3 = "cannot restrict running of" ascii //weight: 1
        $x_1_4 = "\\Protected\\ActiveDesktop" ascii //weight: 1
        $x_1_5 = "%s\\drivers\\etc" ascii //weight: 1
        $x_1_6 = "?advid=%u&lang=" ascii //weight: 1
        $x_1_7 = ".php?v=%u&d=%u&vs=%u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Rogue_Win32_SpySheriff_15963_14
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PestWiper Online Installer" ascii //weight: 1
        $x_1_2 = "PestWiper.dvm" ascii //weight: 1
        $x_2_3 = "69.50.175.179" ascii //weight: 2
        $x_1_4 = {47 45 54 20 2f 74 72 69 61 6c [0-2] 2e 70 68 70 3f 72 65 73 74 3d 25 75 26 76 65 72 3d 25 75 26 61 3d 30 30 30 30 30 30 30 30 20 48 54 54 50 2f 31 2e 30}  //weight: 1, accuracy: Low
        $x_1_5 = "QftuXjqfs" ascii //weight: 1
        $x_1_6 = "Are you sure you wish to cancel" ascii //weight: 1
        $x_1_7 = "Internet connection loss detected. Retry?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_SpySheriff_15963_15
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Pest Trap Online Installer" ascii //weight: 1
        $x_1_2 = "PestTrap.dvm" ascii //weight: 1
        $x_2_3 = "69.50.175.1" ascii //weight: 2
        $x_1_4 = {47 45 54 20 2f 74 72 69 61 6c [0-2] 2e 70 68 70 3f 72 65 73 74 3d 25 75 26 76 65 72 3d 25 75 26 61 3d 30 30 30 30 30 30 [0-2] 20 48 54 54 50 2f 31 2e 30}  //weight: 1, accuracy: Low
        $x_1_5 = "QftuUsbq" ascii //weight: 1
        $x_1_6 = "Are you sure you wish to cancel setup?" ascii //weight: 1
        $x_1_7 = "Internet connection loss detected. Retry?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_SpySheriff_15963_16
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\AdwareRemover" ascii //weight: 1
        $x_2_2 = "69.50.167.28" ascii //weight: 2
        $x_1_3 = "GET /ardownload.php" ascii //weight: 1
        $x_1_4 = {41 64 77 61 72 65 52 65 6d 6f 76 65 72 [0-4] 20 45 6e 64 20 55 73 65 72 20 4c 69 63 65 6e 73 65 20 41 67 72 65 65 6d 65 6e 74}  //weight: 1, accuracy: Low
        $x_1_5 = {41 64 77 61 72 65 52 65 6d 6f 76 65 72 [0-7] 20 53 65 74 75 70}  //weight: 1, accuracy: Low
        $x_1_6 = "Are you sure you wish to cancel setup?" ascii //weight: 1
        $x_1_7 = "Internet connection is unavailable." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_SpySheriff_15963_17
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Spy Trooper Online Installer" ascii //weight: 1
        $x_1_2 = "SpyTrooper.dvm" ascii //weight: 1
        $x_2_3 = "69.50.175.1" ascii //weight: 2
        $x_1_4 = {47 45 54 20 2f 74 72 69 61 6c [0-2] 2e 70 68 70 3f 72 65 73 74 3d 25 75 26 76 65 72 3d 25 75 26 61 3d 30 30 30 30 30 30 [0-2] 20 48 54 54 50 2f 31 2e 30}  //weight: 1, accuracy: Low
        $x_1_5 = "TqzUsppqfs" ascii //weight: 1
        $x_1_6 = "Are you sure you wish to cancel setup?" ascii //weight: 1
        $x_1_7 = "Internet connection loss detected. Retry?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_SpySheriff_15963_18
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Spy Sheriff Online Installer" ascii //weight: 1
        $x_1_2 = "SpySheriff.dvm" ascii //weight: 1
        $x_2_3 = "69.50.175.1" ascii //weight: 2
        $x_2_4 = "69.50.170.83" ascii //weight: 2
        $x_1_5 = {47 45 54 20 2f 74 72 69 61 6c [0-2] 2e 70 68 70 3f 72 65 73 74 3d 25 75 26 76 65 72 3d 25 75 26 61 3d 30 30 30 30 30 30 30 30 20 48 54 54 50 2f 31 2e 30}  //weight: 1, accuracy: Low
        $x_1_6 = "TqzTifsjgg" ascii //weight: 1
        $x_1_7 = "Are you sure you wish to cancel" ascii //weight: 1
        $x_1_8 = "Internet connection loss detected. Retry?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_SpySheriff_15963_19
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 49 45 44 65 66 65 6e 64 65 72 [0-5] 49 45 20 44 65 66 65 6e 64 65 72}  //weight: 1, accuracy: Low
        $x_1_2 = "IE Defender" ascii //weight: 1
        $x_1_3 = "Click Uninstall to start" ascii //weight: 1
        $x_1_4 = "\\iedefender.db1" ascii //weight: 1
        $x_1_5 = "\\iedefender.db2" ascii //weight: 1
        $x_1_6 = "\\iedefender.db3" ascii //weight: 1
        $x_1_7 = "\\iedefender.db4" ascii //weight: 1
        $x_1_8 = "\\iedefender.db5" ascii //weight: 1
        $x_1_9 = "\\iedefender.exe" ascii //weight: 1
        $x_1_10 = "\\uninstall.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_SpySheriff_15963_20
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Spyware scanner and remover. Uninstall.</" ascii //weight: 2
        $x_2_2 = {53 4e 2e 53 70 79 77 61 72 65 4e 6f 55 6e 69 6e 73 74 61 6c 6c 22 0d 0a 20 20 20 20 74}  //weight: 2, accuracy: High
        $x_2_3 = {42 53 2e 55 6e 69 6e 73 74 61 6c 6c 22 0d 0a 20 20 20 20 74 79 70 65 3d 22 77 69 6e 33 32 22 0d 0a 2f}  //weight: 2, accuracy: High
        $x_2_4 = "BS. Uninstall.</des" ascii //weight: 2
        $x_1_5 = "publicKeyToken=\"6595b64144ccf1df" ascii //weight: 1
        $x_1_6 = "VariantChangeTypeEx" ascii //weight: 1
        $x_1_7 = "InitCommonControlsEx" ascii //weight: 1
        $x_1_8 = "GetModuleHandleA" ascii //weight: 1
        $x_1_9 = "GetLastActivePopup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_SpySheriff_15963_21
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Host: download.ssd.com" ascii //weight: 1
        $x_1_2 = "Host: xscanner.spy-shredder.com" ascii //weight: 1
        $x_1_3 = "Cache-Control: no-cache" ascii //weight: 1
        $x_1_4 = "download.spy-shredder.com" ascii //weight: 1
        $x_1_5 = {47 45 54 20 2f 64 6c 70 2e 70 68 70 3f 26 26 6d 3d 30 26 79 64 66 3d 34 32 33 30 39 39 32 26 65 3d 30 30 30 30 30 30 30 30 26 77 3d 5f 5f 5f 5f 5f 5f ?? ?? 26 74 3d 30 26 61 70 7a 78 3d 31 26 61 70 7a 3d 6d 79 61 70 70 2e 65 78 65 20 48 54 54 50 2f 31 2e 30}  //weight: 1, accuracy: Low
        $x_1_6 = "C:\\Windows\\xpupdate.exe" ascii //weight: 1
        $x_1_7 = "C:\\Program Files\\SpyShredder\\SpyShredder.exe" ascii //weight: 1
        $x_1_8 = "69.50.164.27" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_SpySheriff_15963_22
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5a 69 6e 61 70 73 20 41 6e 74 69 2d 53 70 79 77 61 72 65 20 32 30 30 ?? 2e 6c 6e 6b}  //weight: 1, accuracy: Low
        $x_1_2 = {5a 69 6e 61 70 73 32 30 30 ?? 5c 5a 69 6e 61 70 73 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "Zinaps Anti-Spyware is minimized in tray to keep your PC safe. Right click icon to open or exit the program" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_6 = "InternetOpenA" ascii //weight: 1
        $x_1_7 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_SpySheriff_15963_23
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "82"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "GetLastActivePopup" ascii //weight: 10
        $x_10_2 = "NOTICE TO USER:  PLEASE READ THIS CONTRACT CAREFULLY" ascii //weight: 10
        $x_10_3 = "C:\\Program Files\\%s\\%s.lic" ascii //weight: 10
        $x_10_4 = "C:\\Program Files\\%s\\%s.exe" ascii //weight: 10
        $x_10_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" ascii //weight: 10
        $x_10_6 = "ProxyEnable" ascii //weight: 10
        $x_10_7 = "Internet connection is unavailable. Try again?" ascii //weight: 10
        $x_10_8 = "CreateDirectoryA" ascii //weight: 10
        $x_1_9 = "&advid=" ascii //weight: 1
        $x_1_10 = "&u=%u&p=%u %s%s" ascii //weight: 1
        $x_1_11 = "Control:" ascii //weight: 1
        $x_1_12 = "00002654" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_SpySheriff_15963_24
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 64 65 72 2e 6c 69 63 00 00 00 00 79 53 68 72 65 00 00 00 64 64 65 72 5c 53 70 00 65 73 5c 53 70 00 00 00 25 73 25 73 25 73 25 73 25 73 25 73 00 00 00 00 64 65 72 00 79 53 68 72 65 64 00 00 53 70 00 00 61 6d 20 46 69 6c 65 73 5c 00 00 00 43 3a 5c 50 72 6f 67 72 00 00 00 00 25 73 25 73 00 00 00 00 65 73 00 00 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 00 00 25 73 25 73 25 73 25 73 25 73 00 00 65 64 64 65 72 2e 65 78 65 00 00 00 70 79 53 68 72 00 00 00 68 72 65 64 64 65 72 5c 53 00 00 00 6c 65 73 5c 53 70 79 53 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "GET http://download.spy-shredder.com/ssdownload.php?&advid=00001322&u=%u&p=%u&lang=________&vs=%u&%s HTTP/1.0" ascii //weight: 1
        $x_1_3 = "GET /ssdownload.php?&advid=00001322&u=%u&p=%u&lang=________&vs=%u&%s HTTP/1.0" ascii //weight: 1
        $x_1_4 = "Host: download.spy-shredder.com" ascii //weight: 1
        $x_1_5 = "69.50.175.180" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_SpySheriff_15963_25
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Host: download.MalwareAlarm.com" ascii //weight: 1
        $x_1_2 = "Cache-Control: no-cache" ascii //weight: 1
        $x_1_3 = {47 45 54 20 2f 6d 61 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 26 61 64 76 69 64 3d 30 30 30 30 30 30 30 30 26 75 3d 30 26 70 3d 34 32 32 35 34 31 36 26 6c 61 6e 67 3d 5f 5f 5f 5f 5f 5f ?? ?? 26 76 73 3d 30 26 73 77 70 3d 31 26 61 70 78 3d 6d 79 61 70 70 2e 65 78 65 20 48 54 54 50 2f 31 2e 30}  //weight: 1, accuracy: Low
        $x_1_4 = {47 45 54 20 68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 25 73 2e 63 6f 6d 2f 6d 61 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 26 61 64 76 69 64 3d 30 30 30 30 30 30 30 30 26 75 3d 25 75 26 70 3d 25 75 26 6c 61 6e 67 3d 5f 5f 5f 5f 5f 5f ?? ?? 26 76 73 3d 25 75 26 73 77 70 3d 31 26 61 70 78 3d 25 73 20 48 54 54 50 2f 31 2e 30}  //weight: 1, accuracy: Low
        $x_1_5 = "http://www.MalwareAlarm.com/" ascii //weight: 1
        $x_1_6 = "C:\\Program Files\\MalwareAlarm\\MalwareAlarm.exe" ascii //weight: 1
        $x_1_7 = "copy \"C:\\myapp.exe\" \"C:\\Windows\\xpupdate.exe\"" ascii //weight: 1
        $x_1_8 = "MalwareAlarm.lic" ascii //weight: 1
        $x_1_9 = "69.50.175.181" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Rogue_Win32_SpySheriff_15963_26
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/SpySheriff"
        threat_id = "15963"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySheriff"
        severity = "214"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 45 43 54 49 4f 4e 20 38 2e 20 59 4f 55 20 41 47 52 45 45 20 54 48 41 54 20 54 48 49 53 20 41 47 52 45 45 4d 45 4e 54 20 49 53 20 45 4e 46 4f 52 43 45 41 42 4c 45 20 4c 49 4b 45 20 41 4e 59 20 57 52 49 54 54 45 4e 20 4e 45 47 4f 54 49 41 54 45 44 20 41 47 52 45 45 4d 45 4e 54 20 53 49 47 4e 45 44 20 42 59 20 59 4f 55 2e 20 20 49 46 20 59 4f 55 20 44 4f 20 4e 4f 54 20 41 47 52 45 45 2c 20 44 4f 20 4e 4f 54 20 55 53 45 20 54 48 49 53 20 53 4f 46 54 57 41 52 45 2e 20 0d 0a 0d 0a 50 6c 65 61 73 65 20 72 65 66 65 72 20 74 6f 20 74 68 65 20 77 65 62 73 69 74 65 20 66 6f 72 20 74 68 65 20 66 75 6c 6c 20 4c 69 63 65 6e 73 65 20 41 67 72 65 65 6d 65 6e 74 20 74 65 78 74 2e}  //weight: 1, accuracy: High
        $x_1_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 25 73 5c 25 73 2e 6c 69 63 00 00 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 25 73 5c 25 73 00 00 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 25 73 5c 25 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 25 73 5c 25 73 2e 65 78 65 00 00 25 73 20 53 65 74 75 70 00 00 00 00 41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 69 73 68 20 74 6f 20 63 61 6e 63 65 6c 20 73 65 74 75 70 3f 00 00 25 73 20}  //weight: 1, accuracy: High
        $x_1_4 = {49 6e 74 65 72 6e 65 74 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 69 73 20 75 6e 61 76 61 69 6c 61 62 6c 65 2e 20 54 72 79 20 61 67 61 69 6e 3f 00 00 47 45 54 20 2f 31 32 34 2e 70 68 70 3f 26 61 64 76 69 64 3d 30 30 30 30 30 ?? ?? ?? 26 75 3d 25 75 26 70 3d 25 75 20 25 73 25 73 2e 25 73 2e 63 6f 6d 0d 25 73 50 72 61 67 6d 61 3a 20 6e 6f 2d 63 61 63 68 65 0d 25 73 43 61 63 68 65 2d 43 6f 6e 74 72 6f 6c 3a 20 6e 6f 2d 63 61 63 68 65 0d 25 73 0d 25 73 00 00 00 36 39 2e 35 30 2e 31 36 37 2e 32 36 00 00 00 00 47 45 54 20 68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 25 73 2e 63 6f 6d 2f 31 32 34 2e 70 68 70 3f 26 61 64 76 69 64 3d 30 30 30 30 30 ?? ?? ?? 26 75 3d 25 75 26 70 3d 25 75 20 25 73 25 73 2e 25 73 2e 63 6f 6d 0d 25 73}  //weight: 1, accuracy: Low
        $x_1_5 = {00 00 41 6e 74 69 53 70 79 77 61 72 65 53 68 69 65 6c 64 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {4a 42 30 31 00 00 00 00 4a 42 30 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


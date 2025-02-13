rule BrowserModifier_Win32_Xupiter_12203_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Xupiter"
        threat_id = "12203"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Xupiter"
        severity = "64"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "104"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "http://www.xupiter.com/" ascii //weight: 100
        $x_100_2 = "http://www.browserwise.com/" ascii //weight: 100
        $x_100_3 = "http://www.sqwire.com/" ascii //weight: 100
        $x_2_4 = "XUPITER_TOOLBAR" ascii //weight: 2
        $x_2_5 = "SOFTWARE\\Xupiter" ascii //weight: 2
        $x_2_6 = "XupiterCfgLoader" ascii //weight: 2
        $x_2_7 = "popunder.html" ascii //weight: 2
        $x_2_8 = "popunder.cfg" ascii //weight: 2
        $x_2_9 = "CPopunderDoc" ascii //weight: 2
        $x_2_10 = "CPopunderView" ascii //weight: 2
        $x_2_11 = "XupiterToolbar.exe" ascii //weight: 2
        $x_2_12 = "XupiterToolbarLoader.exe" ascii //weight: 2
        $x_2_13 = "XupiterToolbar.DLL" ascii //weight: 2
        $x_2_14 = "XupiterMenu.xml" ascii //weight: 2
        $x_2_15 = "XupiterMenu.dat" ascii //weight: 2
        $x_1_16 = "STARTUP_URL" ascii //weight: 1
        $x_1_17 = "IE Activity" ascii //weight: 1
        $x_2_18 = "Software\\SQ" ascii //weight: 2
        $x_2_19 = "Sqwire, Inc toolbar was installed successfully!" ascii //weight: 2
        $x_2_20 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sqwire" ascii //weight: 2
        $x_2_21 = "SQDesktop.dat" ascii //weight: 2
        $x_2_22 = "SQUpdate.dat" ascii //weight: 2
        $x_2_23 = "C:\\WINDOWS\\SYSTEM32\\sqwire.log" ascii //weight: 2
        $x_2_24 = "6E6DD93E-1FC3-4F43-8AFB-1B7B90C9D3EB" ascii //weight: 2
        $x_104_25 = {70 6f 70 75 6e 64 65 72 2e 68 74 6d 6c [0-32] 70 6f 70 75 6e 64 65 72 2e 63 66 67 [0-32] 53 4f 46 54 57 41 52 45 5c 58 75 70 69 74 65 72 [0-32] 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 46 6f 6c 64 65 72 [0-32] 50 6f 70 75 6e 64 65 72 [0-32] 43 50 6f 70 75 6e 64 65 72 44 6f 63 [0-32] 43 50 6f 70 75 6e 64 65 72 56 69 65 77}  //weight: 104, accuracy: Low
        $x_104_26 = {4f 4c 44 5f 53 45 41 52 43 48 5f 48 4f 4f 4b 53 5f 4c 4f 43 41 4c [0-16] 53 6f 66 74 77 61 72 65 5c 58 75 70 69 74 65 72 [0-16] 4f 4c 44 5f 53 45 41 52 43 48 5f 48 4f 4f 4b 53 5f 43 55 52 52 45 4e 54}  //weight: 104, accuracy: Low
        $x_104_27 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 71 77 69 72 65 2e 63 6f 6d [0-32] 49 6e 74 65 72 6e 65 74 20 43 6f 6e 6e 65 63 74 69 6f 6e 20 54 65 73 74 [0-32] 53 71 77 69 72 65 [0-32] 44 6f 77 6e 6c 6f 61 64 3a [0-32] 66 69 6c 65 2e 70 68 70 3f 66 69 6c 65 3d [0-32] 26 61 69 64 3d [0-32] 66 69 6c 65 69 6e 66 6f 2e 70 68 70 3f 66 69 6c 65 3d [0-32] 26 73 69 64 3d [0-32] 53 6f 66 74 77 61 72 65 5c 53 51}  //weight: 104, accuracy: Low
        $n_300_28 = "Advanced Uninstaller PRO" ascii //weight: -300
        $n_300_29 = "EasySync Pro" ascii //weight: -300
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_2_*))) or
            ((2 of ($x_100_*))) or
            ((1 of ($x_104_*))) or
            (all of ($x*))
        )
}


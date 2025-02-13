rule Trojan_Win32_FakeMalean_2147625004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeMalean"
        threat_id = "2147625004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeMalean"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "update-%d-%.2d-%.2d.dbn.gz" ascii //weight: 20
        $x_20_2 = "GET /update/%d/%d.exe HTTP/1.0" ascii //weight: 20
        $x_20_3 = "if exist \"%s\" goto abc" ascii //weight: 20
        $x_20_4 = "TWindowsSecurityCenter" ascii //weight: 20
        $x_10_5 = "Malware Cleaner" ascii //weight: 10
        $x_10_6 = "nixclean.com" ascii //weight: 10
        $x_5_7 = "http://%s/help.php" ascii //weight: 5
        $x_5_8 = "http://%s/contact.php" ascii //weight: 5
        $x_5_9 = "HomeButton" ascii //weight: 5
        $x_5_10 = "SystemScanButton" ascii //weight: 5
        $x_5_11 = "SecurityButton" ascii //weight: 5
        $x_5_12 = "PrivacyButton" ascii //weight: 5
        $x_5_13 = "UpdateButton" ascii //weight: 5
        $x_5_14 = "SettingsButton" ascii //weight: 5
        $x_5_15 = "Trojan detected!" ascii //weight: 5
        $x_5_16 = "Spyware alarm!" ascii //weight: 5
        $x_5_17 = "Privacy is at risk!" ascii //weight: 5
        $x_5_18 = "Viruses destroyed!" ascii //weight: 5
        $x_5_19 = "Trojan Alert!" ascii //weight: 5
        $x_1_20 = "Win32.Small.ydh" ascii //weight: 1
        $x_1_21 = "Win32.Agent.ahoe" ascii //weight: 1
        $x_1_22 = "JS.Agent.crh" ascii //weight: 1
        $x_1_23 = "Win32.Kido.ih" ascii //weight: 1
        $x_1_24 = "Win32.Zbot.ikh" ascii //weight: 1
        $x_1_25 = "Win32.Agent.mee" ascii //weight: 1
        $x_1_26 = "Win32.QQHelper.aoc" ascii //weight: 1
        $x_1_27 = "Win32.Hupigon.fdnv" ascii //weight: 1
        $x_1_28 = "Win32.Kido.fx" ascii //weight: 1
        $x_1_29 = "CBVirusProtection" ascii //weight: 1
        $x_1_30 = "CBSpywareProtection" ascii //weight: 1
        $x_1_31 = "CBGeneralSecurity" ascii //weight: 1
        $x_1_32 = "CBAutomaticUpdating" ascii //weight: 1
        $x_1_33 = "CBMinimizeToTray" ascii //weight: 1
        $x_1_34 = "CBStartWithWindows" ascii //weight: 1
        $x_1_35 = "CBScanAtStartup" ascii //weight: 1
        $x_1_36 = "CBScaningEveryHour" ascii //weight: 1
        $x_1_37 = "CBDisableSounds" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 13 of ($x_5_*) and 15 of ($x_1_*))) or
            ((1 of ($x_20_*) and 13 of ($x_5_*) and 15 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 11 of ($x_5_*) and 15 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 12 of ($x_5_*) and 10 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 13 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 9 of ($x_5_*) and 15 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 10 of ($x_5_*) and 10 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 11 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 12 of ($x_5_*))) or
            ((2 of ($x_20_*) and 9 of ($x_5_*) and 15 of ($x_1_*))) or
            ((2 of ($x_20_*) and 10 of ($x_5_*) and 10 of ($x_1_*))) or
            ((2 of ($x_20_*) and 11 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*) and 12 of ($x_5_*))) or
            ((2 of ($x_20_*) and 1 of ($x_10_*) and 7 of ($x_5_*) and 15 of ($x_1_*))) or
            ((2 of ($x_20_*) and 1 of ($x_10_*) and 8 of ($x_5_*) and 10 of ($x_1_*))) or
            ((2 of ($x_20_*) and 1 of ($x_10_*) and 9 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*) and 1 of ($x_10_*) and 10 of ($x_5_*))) or
            ((2 of ($x_20_*) and 2 of ($x_10_*) and 5 of ($x_5_*) and 15 of ($x_1_*))) or
            ((2 of ($x_20_*) and 2 of ($x_10_*) and 6 of ($x_5_*) and 10 of ($x_1_*))) or
            ((2 of ($x_20_*) and 2 of ($x_10_*) and 7 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*) and 2 of ($x_10_*) and 8 of ($x_5_*))) or
            ((3 of ($x_20_*) and 5 of ($x_5_*) and 15 of ($x_1_*))) or
            ((3 of ($x_20_*) and 6 of ($x_5_*) and 10 of ($x_1_*))) or
            ((3 of ($x_20_*) and 7 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_20_*) and 8 of ($x_5_*))) or
            ((3 of ($x_20_*) and 1 of ($x_10_*) and 3 of ($x_5_*) and 15 of ($x_1_*))) or
            ((3 of ($x_20_*) and 1 of ($x_10_*) and 4 of ($x_5_*) and 10 of ($x_1_*))) or
            ((3 of ($x_20_*) and 1 of ($x_10_*) and 5 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_20_*) and 1 of ($x_10_*) and 6 of ($x_5_*))) or
            ((3 of ($x_20_*) and 2 of ($x_10_*) and 1 of ($x_5_*) and 15 of ($x_1_*))) or
            ((3 of ($x_20_*) and 2 of ($x_10_*) and 2 of ($x_5_*) and 10 of ($x_1_*))) or
            ((3 of ($x_20_*) and 2 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_20_*) and 2 of ($x_10_*) and 4 of ($x_5_*))) or
            ((4 of ($x_20_*) and 1 of ($x_5_*) and 15 of ($x_1_*))) or
            ((4 of ($x_20_*) and 2 of ($x_5_*) and 10 of ($x_1_*))) or
            ((4 of ($x_20_*) and 3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((4 of ($x_20_*) and 4 of ($x_5_*))) or
            ((4 of ($x_20_*) and 1 of ($x_10_*) and 10 of ($x_1_*))) or
            ((4 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((4 of ($x_20_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((4 of ($x_20_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}


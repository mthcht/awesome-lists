rule Backdoor_Win32_SixMuch_A_2147628456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/SixMuch.A"
        threat_id = "2147628456"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "SixMuch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters" ascii //weight: 5
        $x_5_2 = "rundll32.exe shell32.dll,Control_RunDLL inetcpl.cpl,,0" ascii //weight: 5
        $x_10_3 = "http://www.666t.com/" ascii //weight: 10
        $x_1_4 = "Internet Explorer_TridentCmboBx" ascii //weight: 1
        $x_1_5 = "Internet Explorer_Server" ascii //weight: 1
        $x_1_6 = "IEMonitor.EXE" ascii //weight: 1
        $x_1_7 = "IEMonitor Microsoft " ascii //weight: 1
        $x_1_8 = "safefe" ascii //weight: 1
        $x_10_9 = "_fucking_" ascii //weight: 10
        $x_10_10 = "_smoking_" ascii //weight: 10
        $x_1_11 = "?fid=" ascii //weight: 1
        $x_1_12 = "&ver=" ascii //weight: 1
        $x_1_13 = "domain=" ascii //weight: 1
        $x_1_14 = "%31[A-Za-z]" ascii //weight: 1
        $x_1_15 = "&cid=" ascii //weight: 1
        $x_1_16 = "00.00.00.00" ascii //weight: 1
        $x_1_17 = "*.lnk" ascii //weight: 1
        $x_1_18 = "&tid=" ascii //weight: 1
        $x_1_19 = "; domain=" ascii //weight: 1
        $x_1_20 = "360se" ascii //weight: 1
        $x_1_21 = "char* X1F91AA70608D4BEE88C754EE40EFE279 =\"X1F91AA70608D4BEE88C754EE40EFE279\";" ascii //weight: 1
        $x_1_22 = "char* XF021B9B35B284E639A2F50DACB574023 =\"XF021B9B35B284E639A2F50DACB574023\";" ascii //weight: 1
        $x_1_23 = "char* XCDEC47D341C44484AEE22A076C0FAC39 =\"XCDEC47D341C44484AEE22A076C0FAC39\";" ascii //weight: 1
        $x_1_24 = "char* XE337CF741FCA452E949478F4EEDF6228 =\"XE337CF741FCA452E949478F4EEDF6228\";" ascii //weight: 1
        $x_1_25 = "char* X71F7E86500224A0DB96033CD8FD24437 =\"X71F7E86500224A0DB96033CD8FD24437\";" ascii //weight: 1
        $x_1_26 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\ClassicStartMenu" ascii //weight: 1
        $x_1_27 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\IEXPLORE.EXE" ascii //weight: 1
        $x_1_28 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel" ascii //weight: 1
        $x_1_29 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace\\%s" ascii //weight: 1
        $x_1_30 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" ascii //weight: 1
        $x_1_31 = "AddPostParam" ascii //weight: 1
        $x_1_32 = "FindFirstFileA" ascii //weight: 1
        $x_1_33 = "QuitApp" ascii //weight: 1
        $x_1_34 = "CallNextHookEx" ascii //weight: 1
        $x_1_35 = "InternetGetCookieA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 30 of ($x_1_*))) or
            ((2 of ($x_10_*) and 30 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 25 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 20 of ($x_1_*))) or
            ((3 of ($x_10_*) and 20 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 15 of ($x_1_*))) or
            ((3 of ($x_10_*) and 2 of ($x_5_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}


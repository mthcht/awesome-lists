rule PWS_Win32_Cinmag_A_2147602388_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Cinmag.A"
        threat_id = "2147602388"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmag"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@gmail.com" wide //weight: 1
        $x_1_2 = "<p></p><B>Saved passwords in IE </b><ul>" wide //weight: 1
        $x_1_3 = "<p></p><B>Saved email passwords in Outlook</b><ul>" wide //weight: 1
        $x_1_4 = "<p></p><B>Yahoo messenger passwords</b><ul>" wide //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_6 = "system\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile" wide //weight: 1
        $x_1_7 = "DisableNotifications" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule PWS_Win32_Cinmag_B_2147602389_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Cinmag.B"
        threat_id = "2147602389"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmag"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "73"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Your Yahoo! ID that logged pass Send to it" ascii //weight: 10
        $x_10_2 = "Just type ID don't use  @yahoo.com" ascii //weight: 10
        $x_1_3 = "Disable McAfee AVS" ascii //weight: 1
        $x_1_4 = "Disable Win FireWall xp2" ascii //weight: 1
        $x_1_5 = "Disable Norton AVS" ascii //weight: 1
        $x_1_6 = "Disable MsConfig" ascii //weight: 1
        $x_1_7 = "Disable Regedit" ascii //weight: 1
        $x_1_8 = "Disable Taskmgr xp-2k" ascii //weight: 1
        $x_1_9 = "Disable Y! Save Pass" ascii //weight: 1
        $x_10_10 = "Send Win User" ascii //weight: 10
        $x_10_11 = "Auto Startup" ascii //weight: 10
        $x_10_12 = "Delete Mess Archive" ascii //weight: 10
        $x_10_13 = "Send Computer Name" ascii //weight: 10
        $x_10_14 = "Send Yahoo Password" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Cinmag_C_2147602390_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Cinmag.C"
        threat_id = "2147602390"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Cinmag"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Yahoo" ascii //weight: 10
        $x_10_2 = "Hacked BY" wide //weight: 10
        $x_1_3 = "\\YMagic.dll" wide //weight: 1
        $x_1_4 = "PASS=" wide //weight: 1
        $x_1_5 = "computerName=" wide //weight: 1
        $x_1_6 = "Password=" wide //weight: 1
        $x_1_7 = "Computer Name=" wide //weight: 1
        $x_1_8 = "Norton Antivirus Auto Protect Service" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


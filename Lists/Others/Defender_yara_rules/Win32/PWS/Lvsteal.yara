rule PWS_Win32_Lvsteal_A_2147760653_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Lvsteal.A!MTB"
        threat_id = "2147760653"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Lvsteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "46"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {47 33 f6 8d 45 ec 50 8b d6 03 d2 42 b9 02 00 00 00 8b 45 fc e8 ?? ?? ?? ?? 8b 4d ec 8d 45 f0 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f0 ba 20 00 00 00 e8 ?? ?? ?? ?? 8b d8 8b 45 f8 e8 ?? ?? ?? ?? 85 c0 7e 1d 8b 45 f8 e8 ?? ?? ?? ?? 50 8b c6 5a 8b ca 99 f7 f9 42 8b 45 f8 8a 44 10 ff 32 c3 8b d8 8d 45 e8 8b d3 e8 ?? ?? ?? ?? 8b 55 e8 8b 45 f4 e8 ?? ?? ?? ?? 8b 45 f4 46 4f 75 86}  //weight: 20, accuracy: Low
        $x_20_2 = "\\Mozilla\\Firefox\\profiles.ini" ascii //weight: 20
        $x_1_3 = "Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_4 = "\\logins.json" ascii //weight: 1
        $x_1_5 = "lving hostname %s" ascii //weight: 1
        $x_1_6 = "\\\\.\\SMARTVSD" ascii //weight: 1
        $x_1_7 = "\\\\.\\PhysicalDrive0" ascii //weight: 1
        $x_1_8 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProductName" ascii //weight: 1
        $x_1_9 = "\\prefs.js" ascii //weight: 1
        $x_1_10 = "\\Program Files\\Mozilla Firefox\\firefox.exe" ascii //weight: 1
        $x_1_11 = "\\Program Files (x86)\\Mozilla Firefox\\firefox.exe" ascii //weight: 1
        $x_1_12 = "\\Program Files\\Internet Explorer\\iexplore.exe" ascii //weight: 1
        $x_1_13 = "\\Program Files (x86)\\Internet Explorer\\iexplore.exe" ascii //weight: 1
        $x_1_14 = "Chrome_WidgetWin_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}


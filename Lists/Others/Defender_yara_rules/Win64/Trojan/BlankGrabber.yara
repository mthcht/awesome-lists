rule Trojan_Win64_BlankGrabber_DA_2147850510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlankGrabber.DA!MTB"
        threat_id = "2147850510"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlankGrabber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BlankGrabber" ascii //weight: 1
        $x_1_2 = "Taking screenshot" ascii //weight: 1
        $x_1_3 = "wifi passwords" ascii //weight: 1
        $x_1_4 = "Passwords.txt" ascii //weight: 1
        $x_1_5 = "Blocking AV sites" ascii //weight: 1
        $x_1_6 = "Injecting backdoor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BlankGrabber_DV_2147904574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlankGrabber.DV!MTB"
        threat_id = "2147904574"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlankGrabber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BlankGrabber" ascii //weight: 1
        $x_1_2 = ".StealMinecraft" ascii //weight: 1
        $x_1_3 = ".StealGrowtopia" ascii //weight: 1
        $x_1_4 = "Stealing Steam session" ascii //weight: 1
        $x_1_5 = ".StealUplay" ascii //weight: 1
        $x_1_6 = ".StealRobloxCookies" ascii //weight: 1
        $x_1_7 = ".StealWallets" ascii //weight: 1
        $x_1_8 = ".StealSystemInfo" ascii //weight: 1
        $x_1_9 = ".GetDirectoryTree" ascii //weight: 1
        $x_1_10 = "powershell Get-Clipboard" ascii //weight: 1
        $x_1_11 = ".GetAntivirus" ascii //weight: 1
        $x_1_12 = ".GetTaskList" ascii //weight: 1
        $x_1_13 = ".GetWifiPasswords" ascii //weight: 1
        $x_1_14 = ".TakeScreenshot" ascii //weight: 1
        $x_1_15 = "Blocking AV sites" ascii //weight: 1
        $x_1_16 = "reg delete hkcu\\Software\\Classes\\ms-settings /f" ascii //weight: 1
        $x_1_17 = "ping localhost -n 3 > NUL && del /A H /F \"{}\"" ascii //weight: 1
        $x_1_18 = "Discord.GetTokens" ascii //weight: 1
        $x_1_19 = "ejbalbakoplchlghecdalmeeeajnimhm" ascii //weight: 1
        $x_1_20 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii //weight: 1
        $x_1_21 = ".StealBrowserData.<locals>.run" ascii //weight: 1
        $x_1_22 = ".StealTelegramSessions" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (15 of ($x*))
}


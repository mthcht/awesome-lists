rule Trojan_Win32_HVNCStealer_RPI_2147834660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HVNCStealer.RPI!MTB"
        threat_id = "2147834660"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HVNCStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AVE_MARIA" ascii //weight: 1
        $x_1_2 = "45.12.212.110" ascii //weight: 1
        $x_1_3 = "rundll32.exe shell32.dll,#61" ascii //weight: 1
        $x_1_4 = "cmd.exe /c start " ascii //weight: 1
        $x_1_5 = "chrome.exe" ascii //weight: 1
        $x_1_6 = "profiles.ini" ascii //weight: 1
        $x_1_7 = "firefox.exe" ascii //weight: 1
        $x_1_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" ascii //weight: 1
        $x_1_9 = "Sleep" ascii //weight: 1
        $x_1_10 = "GetTopWindow" ascii //weight: 1
        $x_1_11 = "--no-sandbox --allow-no-sandbox-job" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


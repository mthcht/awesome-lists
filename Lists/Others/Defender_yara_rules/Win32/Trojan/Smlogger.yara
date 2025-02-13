rule Trojan_Win32_Smlogger_SD_2147755415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smlogger.SD!MTB"
        threat_id = "2147755415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smlogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keylogger And Clipboard" ascii //weight: 1
        $x_1_2 = "Telegram Desktop" ascii //weight: 1
        $x_1_3 = "Discord Tokken" ascii //weight: 1
        $x_1_4 = "Search And Upload" ascii //weight: 1
        $x_1_5 = "Screenshot.jpeg" ascii //weight: 1
        $x_1_6 = "\\Log.txt" ascii //weight: 1
        $x_1_7 = "AppData\\Roaming\\Thunderbird\\Profiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smlogger_A_2147755619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smlogger.A!!Smlogger.gen!MTB"
        threat_id = "2147755619"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smlogger"
        severity = "Critical"
        info = "Smlogger: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keylogger And Clipboard" ascii //weight: 1
        $x_1_2 = "Telegram Desktop" ascii //weight: 1
        $x_1_3 = "Discord Tokken" ascii //weight: 1
        $x_1_4 = "Search And Upload" ascii //weight: 1
        $x_1_5 = "Screenshot.jpeg" ascii //weight: 1
        $x_1_6 = "\\Log.txt" ascii //weight: 1
        $x_1_7 = "AppData\\Roaming\\Thunderbird\\Profiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


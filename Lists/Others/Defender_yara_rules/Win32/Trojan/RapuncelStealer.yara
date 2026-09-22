rule Trojan_Win32_RapuncelStealer_Z_2147978570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RapuncelStealer.Z!MTB"
        threat_id = "2147978570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RapuncelStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wallet.dat" ascii //weight: 1
        $x_1_2 = "key4.db" ascii //weight: 1
        $x_1_3 = "logins.json" ascii //weight: 1
        $x_1_4 = "TakeScreenshot" ascii //weight: 1
        $x_1_5 = "KillBrowserProcesses" ascii //weight: 1
        $x_1_6 = "ExtractDiscordTokens" ascii //weight: 1
        $x_1_7 = "password" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


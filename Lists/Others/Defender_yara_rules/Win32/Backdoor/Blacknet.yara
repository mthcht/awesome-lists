rule Backdoor_Win32_Blacknet_GA_2147786679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blacknet.GA!MTB"
        threat_id = "2147786679"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blacknet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 00 6e 00 74 00 69 00 [0-2] 44 00 65 00 62 00 75 00 67 00 67 00 69 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = {41 6e 74 69 [0-2] 44 65 62 75 67 67 69 6e 67}  //weight: 1, accuracy: Low
        $x_1_3 = "AntiVM" ascii //weight: 1
        $x_1_4 = "DisableWD" ascii //weight: 1
        $x_1_5 = ".DDOS" ascii //weight: 1
        $x_1_6 = "BandwidthFlood" ascii //weight: 1
        $x_1_7 = "PostHTTP" ascii //weight: 1
        $x_1_8 = "DiscordToken" ascii //weight: 1
        $x_1_9 = "RemoteDesktop" ascii //weight: 1
        $x_1_10 = "Watchdog" ascii //weight: 1
        $x_1_11 = "SchTask" ascii //weight: 1
        $x_1_12 = "Stealth_Mode" ascii //weight: 1
        $x_1_13 = "Encryption" ascii //weight: 1
        $x_1_14 = "USBSpread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}


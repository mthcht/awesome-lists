rule Trojan_Win32_Arkeistealer_RFA_2147780471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Arkeistealer.RFA!MTB"
        threat_id = "2147780471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Arkeistealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*wallet*.dat" ascii //weight: 1
        $x_1_2 = "\\files\\Wallets" ascii //weight: 1
        $x_1_3 = "\\Electrum-LTC\\wallets\\" ascii //weight: 1
        $x_1_4 = "\\ElectronCash\\wallets\\" ascii //weight: 1
        $x_1_5 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_6 = "GetSystemInfo" ascii //weight: 1
        $x_1_7 = "\\Google\\Chrome\\User Data\\" ascii //weight: 1
        $x_1_8 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_9 = "GetStartupInfoW" ascii //weight: 1
        $x_1_10 = "CPU Count: " ascii //weight: 1
        $x_1_11 = "GetKeyboardLayoutList" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule Trojan_Win32_Arkeistealer_RMB_2147780873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Arkeistealer.RMB!MTB"
        threat_id = "2147780873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Arkeistealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 85 ff 7e ?? 55 8b 2d ?? ?? ?? ?? 83 ff 2d 75 ?? 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 33 81 ff 91 05 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_DebugStealer_AMTB_2147981661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DebugStealer!AMTB"
        threat_id = "2147981661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DebugStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DebugStealer" ascii //weight: 1
        $x_2_2 = "debug_stealer.ps1" ascii //weight: 2
        $x_2_3 = "Starting Browser Stealer" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


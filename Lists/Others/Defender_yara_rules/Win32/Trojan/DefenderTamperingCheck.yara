rule Trojan_Win32_DefenderTamperingCheck_2147784081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DefenderTamperingCheck"
        threat_id = "2147784081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DefenderTamperingCheck"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DisableRealtimeMonitoring $true" wide //weight: 2
        $x_1_2 = "DisableIntrusionPreventionSystem $true" wide //weight: 1
        $x_1_3 = "DisableIOAVProtection $true" wide //weight: 1
        $x_1_4 = "DisableScriptScanning $true" wide //weight: 1
        $x_2_5 = "MAPSReporting Disabled" wide //weight: 2
        $x_1_6 = "SubmitSamplesConsent NeverSend" wide //weight: 1
        $x_1_7 = "DisableBehaviorMonitoring $true" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}


rule Trojan_MSIL_DefenseEvasion_RK_2147819141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DefenseEvasion.RK!MTB"
        threat_id = "2147819141"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DefenseEvasion"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "U0VMRUNUIHBhc3N3b3JkX3ZhbHVlLHVzZXJuYW1lX3ZhbHVlLG9yaWdpbl91cmwgRlJPTSBsb2dpbnM=" ascii //weight: 1
        $x_1_2 = "Y2hyb21lXExvZ2luIERhdGE=" ascii //weight: 1
        $x_1_3 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_4 = "DisableBehaviorMonitoring" ascii //weight: 1
        $x_1_5 = "stop_windows_defender" ascii //weight: 1
        $x_1_6 = "DisableScanOnRealtimeEnable" ascii //weight: 1
        $x_1_7 = "aHR0cDovL2xvY2FsaG9zdC90ZXN0L3BpbmcucGhw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


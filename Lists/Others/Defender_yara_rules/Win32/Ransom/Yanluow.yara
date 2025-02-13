rule Ransom_Win32_Yanluow_A_2147794252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Yanluow.A"
        threat_id = "2147794252"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Yanluow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ".yanluowang" ascii //weight: 3
        $x_1_2 = "net stop WinDefend" ascii //weight: 1
        $x_1_3 = "net stop ShadowProtectSvc" ascii //weight: 1
        $x_1_4 = "net stop MSExchangeSA" ascii //weight: 1
        $x_1_5 = "net stop QBCFMonitorService" ascii //weight: 1
        $x_1_6 = "net stop QuickBooks" ascii //weight: 1
        $x_1_7 = "/c powershell -command \"Get-VM | Stop-VM -Force" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


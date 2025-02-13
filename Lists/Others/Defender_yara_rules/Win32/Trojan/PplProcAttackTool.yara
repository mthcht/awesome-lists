rule Trojan_Win32_PplProcAttackTool_2147914592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PplProcAttackTool"
        threat_id = "2147914592"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PplProcAttackTool"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "215"
        strings_accuracy = "High"
    strings:
        $x_25_1 = "/PPLBlade/driver.go" ascii //weight: 25
        $x_25_2 = "/PPLBlade/handle_openers.go" ascii //weight: 25
        $x_25_3 = "/PPLBlade/housekeeping.go" ascii //weight: 25
        $x_25_4 = "/PPLBlade/process_action_helpers.go" ascii //weight: 25
        $x_25_5 = "/PPLBlade/privilleges.go" ascii //weight: 25
        $x_25_6 = "/PPLBlade/process_actions.go" ascii //weight: 25
        $x_25_7 = "/PPLBlade/service.go" ascii //weight: 25
        $x_25_8 = "/PPLBlade/tools.go" ascii //weight: 25
        $x_1_9 = "main.GetProcExpDriver" ascii //weight: 1
        $x_1_10 = "main.DriverOpenProcess" ascii //weight: 1
        $x_1_11 = "main.WriteDriverOnDisk" ascii //weight: 1
        $x_1_12 = "main.OpenProcessHandle" ascii //weight: 1
        $x_1_13 = "main.DirectOpenProc" ascii //weight: 1
        $x_1_14 = "main.ProcExpOpenProc" ascii //weight: 1
        $x_1_15 = "main.SetUpDriverMode" ascii //weight: 1
        $x_1_16 = "main.miniDumpCallback" ascii //weight: 1
        $x_1_17 = "main.ptrToMinidumpCallbackInput" ascii //weight: 1
        $x_1_18 = "main.ptrToMinidumpCallbackOutput" ascii //weight: 1
        $x_1_19 = "main.setNewCallbackOutput" ascii //weight: 1
        $x_1_20 = "main.copyDumpBytes" ascii //weight: 1
        $x_1_21 = "main.MiniDumpGetBytes" ascii //weight: 1
        $x_1_22 = "main.SendBytesRaw" ascii //weight: 1
        $x_1_23 = "main.SendBytesSMB" ascii //weight: 1
        $x_1_24 = "main.DeobfuscateDump" ascii //weight: 1
        $x_1_25 = "main.CreateService" ascii //weight: 1
        $x_1_26 = "main.VerifyServiceConfig" ascii //weight: 1
        $x_1_27 = "main.VerifyServiceRunning" ascii //weight: 1
        $x_1_28 = "main.RemoveService" ascii //weight: 1
        $x_1_29 = "main.updateSidTypeImported" ascii //weight: 1
        $x_1_30 = "main.updateStartUpImported" ascii //weight: 1
        $x_1_31 = "main.toStringBlockImported" ascii //weight: 1
        $x_1_32 = "main.updateDescriptionImported" ascii //weight: 1
        $x_1_33 = "main.ValidateArguments" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_25_*) and 15 of ($x_1_*))) or
            (all of ($x*))
        )
}


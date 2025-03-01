rule MonitoringTool_Win32_SCKeyLog_10817_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SCKeyLog"
        threat_id = "10817"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SCKeyLog"
        severity = "6"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {25 73 5c 25 73 2e 64 6c 6c 00 00 00 61 62 00 00 25 73 5c 25 73 2e 65 78 65 00 00 00 57 4c 45 76 74 55 6e 6c 6f 63 6b 00}  //weight: 3, accuracy: High
        $x_1_2 = "WLEvtStopScreenSaver" ascii //weight: 1
        $x_1_3 = "WLEvtStartScreenSaver" ascii //weight: 1
        $x_1_4 = "WLEvtShutdown" ascii //weight: 1
        $x_1_5 = "WLEvtLock" ascii //weight: 1
        $x_3_6 = {49 6d 70 65 72 73 6f 6e 61 74 65 00 41 73 79 6e 63 68 72 6f 6e 6f 75 73}  //weight: 3, accuracy: High
        $x_3_7 = "KLShared" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_SCKeyLog_10817_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SCKeyLog"
        threat_id = "10817"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SCKeyLog"
        severity = "6"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WLEShutdown" ascii //weight: 1
        $x_1_2 = "WLEStartScreenSaver" ascii //weight: 1
        $x_1_3 = "WLEStopScreenSaver" ascii //weight: 1
        $x_4_4 = "ACUTE/CEDILLA" ascii //weight: 4
        $x_5_5 = "AutoKill: This Engine will delete itself after %d days from now." ascii //weight: 5
        $x_5_6 = "WARNING: LAST REPORT DUE TO SELF-DELETE" ascii //weight: 5
        $x_4_7 = "NextPart_000_01C19920.83032BC7" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_Win32_SCKeyLog_10817_2
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/SCKeyLog"
        threat_id = "10817"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SCKeyLog"
        severity = "6"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WLEventLogon" ascii //weight: 1
        $x_1_2 = "WLEventShutdown" ascii //weight: 1
        $x_1_3 = "WLEventStartScreenSaver" ascii //weight: 1
        $x_1_4 = "WLEventStartup" ascii //weight: 1
        $x_1_5 = "WLEventStopScreenSaver" ascii //weight: 1
        $x_1_6 = "WLEventUnlock" ascii //weight: 1
        $x_2_7 = "%d-%m-%y %H:%M:%S" ascii //weight: 2
        $x_2_8 = "Host (user): %s (%s)" ascii //weight: 2
        $x_2_9 = "Log started at %s" ascii //weight: 2
        $x_2_10 = "Process ended" ascii //weight: 2
        $x_2_11 = "Process started" ascii //weight: 2
        $x_1_12 = "<WIN-START>" ascii //weight: 1
        $x_1_13 = "<WIN-CTXT>" ascii //weight: 1
        $x_1_14 = "<NUMLOCK>" ascii //weight: 1
        $x_1_15 = "<SCRLOCK>" ascii //weight: 1
        $x_1_16 = "<PRNTSCR>" ascii //weight: 1
        $x_1_17 = "<CPSLOCK>" ascii //weight: 1
        $x_1_18 = "LBUTTONDBLCLK" ascii //weight: 1
        $x_1_19 = "RBUTTONCLK>" ascii //weight: 1
        $x_1_20 = "MBUTTONCLK" ascii //weight: 1
        $x_1_21 = "MBUTTONDBLCLK" ascii //weight: 1
        $x_1_22 = "UNKMOUSE" ascii //weight: 1
        $x_3_23 = "Vtfs!&t!vompdlfe!tztufn" ascii //weight: 3
        $x_3_24 = "Tdsffotbwfs!tupqqfe" ascii //weight: 3
        $x_3_25 = "Tztufn" ascii //weight: 3
        $x_3_26 = "!tubsufe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((15 of ($x_1_*))) or
            ((1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((3 of ($x_3_*) and 6 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((4 of ($x_3_*) and 3 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}


rule HackTool_Win32_ProcKiller_B_2147648473_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/ProcKiller.B"
        threat_id = "2147648473"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcKiller"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "62"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "WinStationTerminateProcess" ascii //weight: 10
        $x_10_2 = "CsrGetProcessId" ascii //weight: 10
        $x_10_3 = "DuplicateHandle" ascii //weight: 10
        $x_10_4 = {68 03 00 01 40 8b 45 f8 50 ff 15}  //weight: 10, accuracy: High
        $x_10_5 = {89 45 a8 89 45 ac 89 45 b0 89 45 b4 89 45 b8 89 45 bc 81 7d c8 00 00 00 80 0f 83 a8 00 00 00 ?? ?? 6a 1c 8d 45 a4 50 8b 4d c8 51 8b 55 f8 52 ff 15 ?? ?? 41 00 [0-9] 8b 45 b0 50 ff 15 ?? ?? 41 00 [0-10] 89 45 98 8b 45 b0 50 68 90 00 00 00 8b 4d 98 51}  //weight: 10, accuracy: Low
        $x_10_6 = {c7 45 cc 01 00 00 00 8b 45 e4 89 45 d0 8b 4d e8 89 4d d4 0f b6 45 0c f7 d8 1b c0 83 e0 02 89 45 d8 8b f4 6a 00 6a 00 6a 00 8d 45 cc 50 6a 00 8b 4d f4 51 ff 15}  //weight: 10, accuracy: High
        $x_1_7 = "SuspendThread" ascii //weight: 1
        $x_1_8 = "LookupPrivilegeValue" ascii //weight: 1
        $x_1_9 = {6a 00 6a 00 68 60 f0 00 00 8b 45 08 50 ff 15}  //weight: 1, accuracy: High
        $x_1_10 = {6a 00 6a 00 6a 12 8b 45 08 50 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


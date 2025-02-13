rule TrojanSpy_WinNT_Tracklogger_A_2147572414_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:WinNT/Tracklogger.gen!A"
        threat_id = "2147572414"
        type = "TrojanSpy"
        platform = "WinNT: WinNT"
        family = "Tracklogger"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\Device\\Rtvcan" wide //weight: 2
        $x_2_2 = "\\DosDevices\\Rtvcan" wide //weight: 2
        $x_2_3 = "\\Device\\KeyboardClass0" wide //weight: 2
        $x_3_4 = "Rtvcan: Entering KeyboardAttach" ascii //weight: 3
        $x_3_5 = "Rtvcan: Couldn't attach to target device" ascii //weight: 3
        $x_3_6 = "Rtvcan: Couldn't get target device object pointer" ascii //weight: 3
        $x_3_7 = "Rtvcan: Couldn't create filter device" ascii //weight: 3
        $x_3_8 = "Rtvcan: Entering KeyboardDetach" ascii //weight: 3
        $x_3_9 = "Rtvcan: Couldn't detach. Someone sits over" ascii //weight: 3
        $x_3_10 = "Rtvcan: Filter device is still attached" ascii //weight: 3
        $x_3_11 = "Rtvcan: Filter device detached" ascii //weight: 3
        $x_3_12 = "Rtvcan: Entering CDO_DispatchCreate" ascii //weight: 3
        $x_3_13 = "Rtvcan: Entering CDO_DispatchClose" ascii //weight: 3
        $x_6_14 = {6a 00 68 4b 53 70 79 6a 10 6a 00 6a 00 6a 00 ff 35}  //weight: 6, accuracy: High
        $x_8_15 = {83 25 34 0f 01 00 00 83 25 38 0f 01 00 00 83 25 28 0f 01 00 00 83 25 3c 0f 01 00 00 83 25 40 0f 01 00 00 8b 45 08 b9 1c}  //weight: 8, accuracy: High
        $x_3_16 = {49 c7 44 88 38 ?? ?? 01 00 0b c9 75 f3 c7 40}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_3_*) and 2 of ($x_2_*))) or
            ((11 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 8 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 9 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 10 of ($x_3_*))) or
            ((1 of ($x_8_*) and 7 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_8_*) and 8 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 9 of ($x_3_*))) or
            ((1 of ($x_8_*) and 1 of ($x_6_*) and 5 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_6_*) and 6 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_6_*) and 7 of ($x_3_*))) or
            (all of ($x*))
        )
}


rule Backdoor_Win32_Wisdoor_2147574045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wisdoor"
        threat_id = "2147574045"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wisdoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "wisdom" ascii //weight: 4
        $x_4_2 = "88FinalSolution" ascii //weight: 4
        $x_4_3 = "DCC console" ascii //weight: 4
        $x_2_4 = "scripts/%2e" ascii //weight: 2
        $x_1_5 = "amateur video" ascii //weight: 1
        $x_1_6 = "KeySpy" ascii //weight: 1
        $x_1_7 = "capturing" ascii //weight: 1
        $x_1_8 = "SetWindowsHook" ascii //weight: 1
        $x_1_9 = "USER %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}


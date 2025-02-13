rule HackTool_Win32_Cymulion_2147783103_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Cymulion"
        threat_id = "2147783103"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Cymulion"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Global\\CYMULATE_EDR" ascii //weight: 2
        $x_2_2 = "CymulateEDRScenarioExecutor" ascii //weight: 2
        $x_1_3 = {46 00 69 00 6c 00 65 00 73 00 5c 00 63 00 79 00 6d 00 75 00 6c 00 61 00 74 00 65 00 5c 00 65 00 64 00 72 00 5c 00 [0-24] 3c 00 43 00 79 00 6d 00 41 00 72 00 67 00 73 00 3e 00}  //weight: 1, accuracy: Low
        $x_1_4 = {46 69 6c 65 73 5c 63 79 6d 75 6c 61 74 65 5c 65 64 72 5c [0-24] 3c 43 79 6d 41 72 67 73 3e}  //weight: 1, accuracy: Low
        $x_1_5 = "NativeRansomeware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


rule MonitoringTool_Win32_Orbond_A_134886_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/Orbond.A"
        threat_id = "134886"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Orbond"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 6f 6f 6b 65 64 00 48 6f 6f 6b 4b 65 79 62 6f 61 72 64 00 55 6e 68 6f 6f 6b 4b 65 79 62 6f 61 72 64 00 4b 65 79 62 6f 61 72 64 43 61 6c 6c 62 61 63 6b}  //weight: 10, accuracy: High
        $x_10_2 = {56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 [0-2] 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72}  //weight: 10, accuracy: Low
        $x_10_3 = {55 00 53 00 45 00 52 00 4e 00 41 00 4d 00 45 [0-3] 66 00 74 00 70 00 3a 00 2f 00 2f}  //weight: 10, accuracy: Low
        $x_10_4 = "ATTRIB -H \"{executable}\"" wide //weight: 10
        $x_1_5 = "[CTRL]" wide //weight: 1
        $x_1_6 = "[TAB]" wide //weight: 1
        $x_1_7 = "[DEL]" wide //weight: 1
        $x_1_8 = "[CAPS]" wide //weight: 1
        $x_1_9 = "[RArrow]" wide //weight: 1
        $x_1_10 = "[PageUp]" wide //weight: 1
        $x_1_11 = "[Home]" wide //weight: 1
        $x_1_12 = "[NumLock]" wide //weight: 1
        $x_1_13 = "[LWindows]" wide //weight: 1
        $x_1_14 = "[MENU]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


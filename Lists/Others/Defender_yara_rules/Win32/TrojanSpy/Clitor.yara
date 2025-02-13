rule TrojanSpy_Win32_Clitor_A_2147725366_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Clitor.A!bit"
        threat_id = "2147725366"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Clitor"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/wp-content/plugins/WPSecurity/load.php" wide //weight: 1
        $x_1_2 = "/wp-content/plugins/WPSecurity/data/" wide //weight: 1
        $x_1_3 = {00 00 31 00 66 00 34 00 35 00 64 00 32 00 36 00 33 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "4,2|3,3|2,4" wide //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_6 = "cmd /v/c (set f=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


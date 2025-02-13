rule TrojanDropper_Win32_Lespy_A_2147582301_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Lespy.gen!A"
        threat_id = "2147582301"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Lespy"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "{e3a729da-eabc-df50-1842-dfd682644311}" ascii //weight: 10
        $x_5_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\%s" ascii //weight: 5
        $x_10_3 = {73 63 72 69 70 74 00 6d 79 63 6c 6f 73 65 65 76 65 6e 74 67 6c 6f 62 61 66 72 61 6d 65 72 6c 31 00 3a 6c 0d 0a 64 65 6c 20 25 73 0d 0a 69 66 [0-1] 65 78 69 73 74 20 25 73 20 67 6f 74 6f 20 6c 0d 0a 64 65 6c 20 25 73 00 64 65 6c 74 2e 62 61 74 00 6f 70 65 6e}  //weight: 10, accuracy: Low
        $x_3_4 = "HOOK_DLL" ascii //weight: 3
        $x_3_5 = "mycloseeventglobaframerl1" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_3_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}


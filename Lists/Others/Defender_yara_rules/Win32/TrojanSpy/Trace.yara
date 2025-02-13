rule TrojanSpy_Win32_Trace_A_2147598179_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Trace.A"
        threat_id = "2147598179"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Trace"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {3a 54 72 79 00 00 00 00 ff ff ff ff 05 00 00 00 44 65 6c 20 22 00 00 00 ff ff ff ff 01 00 00 00 22 00 00 00 ff ff ff ff 0a 00 00 00 49 66 20 45 78 69 73 74 20 22 00 00 ff ff ff ff 09 00 00 00 20 47 6f 74 6f 20 54 72 79 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = "/ver.php?no=" ascii //weight: 2
        $x_2_3 = {00 73 76 63 73 2e 65 78 65}  //weight: 2, accuracy: High
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Trace Service" ascii //weight: 1
        $x_1_6 = "/install /silent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}


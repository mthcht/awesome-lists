rule TrojanSpy_Win32_Ballog_A_2147666318_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ballog.A"
        threat_id = "2147666318"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ballog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\Logs\\%s-[%s]-[%s@%s].txt" ascii //weight: 1
        $x_1_2 = {43 68 61 73 65 2e 63 6f 6d 00 66 69 64 65 6c 69 74 79 2e 63 6f 6d 00 26 53 53 4e 3d 00 26 50 49 4e 3d}  //weight: 1, accuracy: High
        $x_1_3 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 00 2d 6d 20 25 73 00 72 62 2b 00 41 50 50 44 41 54 41 00 25 73 5c 6d 73 6e 74 73 72 76}  //weight: 1, accuracy: High
        $x_1_4 = "1:127.0.0.1:8080;3:127.0.0.1:80;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


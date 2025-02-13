rule TrojanProxy_Win32_Hostile_A_2147611714_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Hostile.A"
        threat_id = "2147611714"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hostile"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 69 6c 65 20 74 72 61 6e 73 20 66 61 69 6c 2e 00 00 00 00 31 30 38 20 25 64 2e 00 46 69 6c 65 20 74 72 61 6e 73 20 73 75 63 63 65 73 73 2e 00 4e 4f 20 46 49 4c 45 20 00 00 00 00 31 30 36 20 25 64 2e 00 31 30 35 20 25 64 2e 00}  //weight: 1, accuracy: High
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "GET http://" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


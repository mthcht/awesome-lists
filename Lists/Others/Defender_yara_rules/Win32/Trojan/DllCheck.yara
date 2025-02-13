rule Trojan_Win32_DllCheck_A_2147750691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllCheck.A!MSR"
        threat_id = "2147750691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllCheck"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 10 80 ca 60 03 da d1 e3 03 45 10 8a 08 84 c9 e0 ee 33 c0 8b 4d 0c 3b d9 74 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_T1070_001_ClearWindowsEventLogs_A_2147846079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/T1070_001_ClearWindowsEventLogs.A"
        threat_id = "2147846079"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "T1070_001_ClearWindowsEventLogs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "event::clear" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


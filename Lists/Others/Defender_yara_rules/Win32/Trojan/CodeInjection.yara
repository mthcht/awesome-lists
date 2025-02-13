rule Trojan_Win32_CodeInjection_B_2147796654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CodeInjection.B!ibt"
        threat_id = "2147796654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CodeInjection"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FindTheRightPID" ascii //weight: 1
        $x_1_2 = "NtCreateSection" ascii //weight: 1
        $x_1_3 = "NtMapViewOfSection" ascii //weight: 1
        $x_1_4 = "NtCreateThreadEx" ascii //weight: 1
        $x_1_5 = "NtOpenProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_ClearEventLogViaWevtutil_A_2147924627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClearEventLogViaWevtutil.A"
        threat_id = "2147924627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClearEventLogViaWevtutil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "wevtutil.exe cl attackiq_" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


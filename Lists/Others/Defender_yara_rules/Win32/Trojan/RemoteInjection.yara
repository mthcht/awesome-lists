rule Trojan_Win32_RemoteInjection_ZPA_2147934568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemoteInjection.ZPA"
        threat_id = "2147934568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemoteInjection"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lsadump::lsa" wide //weight: 1
        $x_1_2 = " /inject " wide //weight: 1
        $x_1_3 = " /id:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


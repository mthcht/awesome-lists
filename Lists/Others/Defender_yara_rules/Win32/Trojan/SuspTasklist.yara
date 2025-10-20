rule Trojan_Win32_SuspTasklist_MK_2147955557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspTasklist.MK"
        threat_id = "2147955557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspTasklist"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tasklist" ascii //weight: 1
        $x_1_2 = "-v" wide //weight: 1
        $x_1_3 = "/v" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


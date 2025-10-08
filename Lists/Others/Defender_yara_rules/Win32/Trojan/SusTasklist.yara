rule Trojan_Win32_SusTasklist_MK_2147954092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusTasklist.MK"
        threat_id = "2147954092"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusTasklist"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tasklist" ascii //weight: 1
        $x_1_2 = "-v" wide //weight: 1
        $x_1_3 = "/v" wide //weight: 1
        $n_1_4 = "a453e881-26a8-4973-bb2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}


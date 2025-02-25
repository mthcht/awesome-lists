rule Trojan_Win32_DataExfiltration_ZPA_2147934419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DataExfiltration.ZPA"
        threat_id = "2147934419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DataExfiltration"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "curl" wide //weight: 10
        $x_10_2 = " -k -F " wide //weight: 10
        $x_10_3 = "file=@" wide //weight: 10
        $x_1_4 = " http://" wide //weight: 1
        $x_1_5 = " https://" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


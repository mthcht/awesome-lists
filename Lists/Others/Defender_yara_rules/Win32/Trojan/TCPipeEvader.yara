rule Trojan_Win32_TCPipeEvader_2147969137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TCPipeEvader"
        threat_id = "2147969137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TCPipeEvader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "mshta" wide //weight: 2
        $x_12_2 = "/d1.pool4883.pw" wide //weight: 12
        $x_12_3 = "/us1.somepools555.pw" wide //weight: 12
        $x_1_4 = "\\\"\\microsoft\\windows\\edp\\edp app update" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_12_*))) or
            (all of ($x*))
        )
}


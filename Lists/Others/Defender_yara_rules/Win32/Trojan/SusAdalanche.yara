rule Trojan_Win32_SusAdalanche_A_2147959229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusAdalanche.A"
        threat_id = "2147959229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusAdalanche"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "adalanche-collector.exe" ascii //weight: 1
        $x_1_2 = "--outputpath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


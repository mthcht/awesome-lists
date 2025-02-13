rule Trojan_Win32_Coppest_A_2147761412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coppest.A"
        threat_id = "2147761412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coppest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = " -nop -noni -executionpolicy bypass " wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


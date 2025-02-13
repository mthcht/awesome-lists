rule Trojan_Win32_OfficeLnkExecution_A_2147769863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OfficeLnkExecution.A"
        threat_id = "2147769863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OfficeLnkExecution"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {76 00 65 00 72 00 63 00 6c 00 73 00 69 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "/c {00021401-0000-0000-c000-000000000046}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


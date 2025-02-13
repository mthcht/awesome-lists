rule Trojan_Win32_MaftaCorrupter_A_2147772525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MaftaCorrupter.A"
        threat_id = "2147772525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MaftaCorrupter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cd c:\\:$i30:$bitmap" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


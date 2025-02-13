rule Trojan_Win32_Networm_A_2147812357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Networm.A"
        threat_id = "2147812357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Networm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/c net session /delete /y > nul" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_LsassDump_G_2147812360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LsassDump.G"
        threat_id = "2147812360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LsassDump"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "secretsdump" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


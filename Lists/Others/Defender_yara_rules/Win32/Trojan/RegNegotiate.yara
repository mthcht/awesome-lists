rule Trojan_Win32_RegNegotiate_A_2147829509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RegNegotiate.A"
        threat_id = "2147829509"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RegNegotiate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" wide //weight: 10
        $x_10_2 = "/v Negotiate" wide //weight: 10
        $x_1_3 = "/t REG_DWORD /d 0x1" wide //weight: 1
        $x_1_4 = "/t REG_DWORD /d 1" wide //weight: 1
        $x_1_5 = "/t REG_DWORD /d 0x00000001" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


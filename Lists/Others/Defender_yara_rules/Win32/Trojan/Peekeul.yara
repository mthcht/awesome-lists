rule Trojan_Win32_Peekeul_A_2147744653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Peekeul.A"
        threat_id = "2147744653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Peekeul"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell.exe" wide //weight: 10
        $x_10_2 = "hidden" wide //weight: 10
        $x_10_3 = "JABzAD0AKABbAFQAZQB4A" wide //weight: 10
        $x_10_4 = "AcABvAHcAZQByAHMAaABlAGwAbAAgACQAcwA=" wide //weight: 10
        $x_10_5 = "SQBnAEEAbQBBAEMAZwBBAEkAQQBBAGsAJwArACgATgBl" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


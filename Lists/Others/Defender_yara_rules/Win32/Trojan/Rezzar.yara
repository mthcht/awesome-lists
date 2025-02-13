rule Trojan_Win32_Rezzar_A_2147793859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rezzar.A"
        threat_id = "2147793859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rezzar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell.exe" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Mestap_A_2147733867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mestap.A"
        threat_id = "2147733867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mestap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "about:<script>" wide //weight: 1
        $x_1_2 = ".RegRead(\"HKCU\\software\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


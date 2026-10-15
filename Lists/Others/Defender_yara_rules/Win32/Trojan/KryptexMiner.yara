rule Trojan_Win32_KryptexMiner_ZA_2147980386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KryptexMiner.ZA!MTB"
        threat_id = "2147980386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KryptexMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "--url stratum+ssl:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


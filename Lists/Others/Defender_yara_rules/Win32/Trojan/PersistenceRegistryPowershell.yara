rule Trojan_Win32_PersistenceRegistryPowershell_2147797963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PersistenceRegistryPowershell"
        threat_id = "2147797963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PersistenceRegistryPowershell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


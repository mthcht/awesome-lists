rule Trojan_Win32_SusBoot_A_2147954097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusBoot.A"
        threat_id = "2147954097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusBoot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bcdedit.exe" ascii //weight: 1
        $x_1_2 = "-v" wide //weight: 1
        $n_1_3 = "a453e881-26a8-4973-bg2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}


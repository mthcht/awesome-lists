rule Trojan_Win32_SuspBoot_A_2147955562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspBoot.A"
        threat_id = "2147955562"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspBoot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bcdedit.exe" ascii //weight: 1
        $x_1_2 = "-v" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


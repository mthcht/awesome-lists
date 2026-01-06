rule Trojan_Win32_SuspNetOnHVA_A_2147960563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspNetOnHVA.A!hva"
        threat_id = "2147960563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspNetOnHVA"
        severity = "Critical"
        info = "hva: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\net.exe" wide //weight: 1
        $x_1_2 = "\\net1.exe" wide //weight: 1
        $x_10_3 = "/add" wide //weight: 10
        $x_10_4 = "group domain admins" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


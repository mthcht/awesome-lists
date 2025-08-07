rule Trojan_Win32_DomainAdminsWho_AM_2147948658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DomainAdminsWho.AM"
        threat_id = "2147948658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DomainAdminsWho"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sb_" wide //weight: 1
        $x_1_2 = "_bs >nul" ascii //weight: 1
        $x_1_3 = "net group \"domain admins\" /domain & exit" ascii //weight: 1
        $x_1_4 = "whoami & exit" ascii //weight: 1
        $n_1_5 = "fg06e39e-7876-4ba3-beee-42bd80ff363b" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}


rule Trojan_Win32_TrustedInstallerHijack_A_2147789298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrustedInstallerHijack.A"
        threat_id = "2147789298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrustedInstallerHijack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 74 00 72 00 75 00 73 00 74 00 65 00 64 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 20 00 62 00 69 00 6e 00 70 00 61 00 74 00 68 00 [0-2] 3d 00}  //weight: 1, accuracy: Low
        $n_1_2 = ":\\lenovoquickfix\\" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_TrustedInstallerHijack_A_2147789298_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrustedInstallerHijack.A"
        threat_id = "2147789298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrustedInstallerHijack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 74 00 72 00 75 00 73 00 74 00 65 00 64 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 20 00 62 00 69 00 6e 00 70 00 61 00 74 00 68 00 [0-2] 3d 00}  //weight: 1, accuracy: Low
        $n_1_2 = ":\\lenovoquickfix\\" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}


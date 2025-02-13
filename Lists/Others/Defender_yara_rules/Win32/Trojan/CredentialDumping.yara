rule Trojan_Win32_CredentialDumping_A_2147805776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CredentialDumping.A!reg"
        threat_id = "2147805776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CredentialDumping"
        severity = "Critical"
        info = "reg: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $n_10_1 = "regbackup3" wide //weight: -10
        $n_10_2 = "\\rapid7\\" wide //weight: -10
        $x_1_3 = "reg.exe" wide //weight: 1
        $x_1_4 = " save hklm\\system " wide //weight: 1
        $x_1_5 = " \\\\tsclient\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}


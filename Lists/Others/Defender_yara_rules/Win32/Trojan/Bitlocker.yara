rule Trojan_Win32_Bitlocker_A_2147795182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bitlocker.A!rsm"
        threat_id = "2147795182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitlocker"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE /f" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bitlocker_B_2147795183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bitlocker.B!rsm"
        threat_id = "2147795183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitlocker"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE" wide //weight: 10
        $x_10_2 = "EnableBDEWithNoTPM" wide //weight: 10
        $x_10_3 = "add" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bitlocker_C_2147795184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bitlocker.C!rsm"
        threat_id = "2147795184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitlocker"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE" wide //weight: 10
        $n_10_2 = "RecoveryKeyMessageSource" wide //weight: -10
        $x_10_3 = "RecoveryKeyMessage" wide //weight: 10
        $x_10_4 = "add" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_Bitlocker_D_2147795185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bitlocker.D!rsm"
        threat_id = "2147795185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitlocker"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE" wide //weight: 10
        $x_10_2 = "RecoveryKeyMessageSource" wide //weight: 10
        $x_10_3 = "add" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bitlocker_E_2147795186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bitlocker.E!rsm"
        threat_id = "2147795186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitlocker"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE" wide //weight: 10
        $x_10_2 = "RecoveryKeyUrl" wide //weight: 10
        $x_10_3 = "add" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bitlocker_F_2147795187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bitlocker.F!rsm"
        threat_id = "2147795187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitlocker"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "-command install-windowsfeature bitlocker -restart" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bitlocker_G_2147795188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bitlocker.G!rsm"
        threat_id = "2147795188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitlocker"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {61 00 74 00 74 00 72 00 69 00 62 00 2e 00 65 00 78 00 65 00 [0-4] 2d 00 73 00 20 00 2d 00 68 00 20 00 [0-48] 2a 00 2e 00 42 00 45 00 4b 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bitlocker_H_2147795189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bitlocker.H!rsm"
        threat_id = "2147795189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitlocker"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {64 00 65 00 6c 00 20 00 [0-48] 2a 00 2e 00 42 00 45 00 4b 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bitlocker_I_2147795190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bitlocker.I!rsm"
        threat_id = "2147795190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitlocker"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6d 00 61 00 6e 00 61 00 67 00 65 00 2d 00 62 00 64 00 65 00 [0-18] 2d 00 6f 00 6e 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bitlocker_K_2147795191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bitlocker.K!rsm"
        threat_id = "2147795191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitlocker"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE" wide //weight: 10
        $x_10_2 = "ActiveDirectoryBackup" wide //weight: 10
        $x_10_3 = "add" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bitlocker_L_2147795192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bitlocker.L!rsm"
        threat_id = "2147795192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitlocker"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE" wide //weight: 10
        $x_10_2 = "ActiveDirectoryInfoToStore" wide //weight: 10
        $x_10_3 = "add" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bitlocker_M_2147795193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bitlocker.M!rsm"
        threat_id = "2147795193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitlocker"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE" wide //weight: 10
        $x_10_2 = "RequireActiveDirectoryBackup" wide //weight: 10
        $x_10_3 = "add" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bitlocker_N_2147795194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bitlocker.N!rsm"
        threat_id = "2147795194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bitlocker"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\FVE" wide //weight: 10
        $x_10_2 = "UseAdvancedStartup" wide //weight: 10
        $x_10_3 = "add" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


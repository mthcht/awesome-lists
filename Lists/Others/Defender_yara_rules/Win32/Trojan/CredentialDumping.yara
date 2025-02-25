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

rule Trojan_Win32_CredentialDumping_ZPA_2147934398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CredentialDumping.ZPA"
        threat_id = "2147934398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CredentialDumping"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 00 65 00 67 00 [0-10] 20 00 73 00 61 00 76 00 65 00 20 00 68 00 6b 00 6c 00 6d 00 5c 00 73 00 61 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_2 = {72 00 65 00 67 00 [0-10] 20 00 73 00 61 00 76 00 65 00 20 00 68 00 6b 00 6c 00 6d 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {72 00 65 00 67 00 [0-10] 20 00 73 00 61 00 76 00 65 00 20 00 68 00 6b 00 6c 00 6d 00 5c 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00}  //weight: 1, accuracy: Low
        $x_1_4 = {72 00 65 00 67 00 [0-10] 20 00 73 00 61 00 76 00 65 00 20 00 68 00 6b 00 65 00 79 00 5f 00 6c 00 6f 00 63 00 61 00 6c 00 5f 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 73 00 61 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_5 = {72 00 65 00 67 00 [0-10] 20 00 73 00 61 00 76 00 65 00 20 00 68 00 6b 00 65 00 79 00 5f 00 6c 00 6f 00 63 00 61 00 6c 00 5f 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_6 = {72 00 65 00 67 00 [0-10] 20 00 73 00 61 00 76 00 65 00 20 00 68 00 6b 00 65 00 79 00 5f 00 6c 00 6f 00 63 00 61 00 6c 00 5f 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00}  //weight: 1, accuracy: Low
        $x_1_7 = {72 00 65 00 67 00 [0-10] 20 00 65 00 78 00 70 00 6f 00 72 00 74 00 20 00 68 00 6b 00 6c 00 6d 00 5c 00 73 00 61 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_8 = {72 00 65 00 67 00 [0-10] 20 00 65 00 78 00 70 00 6f 00 72 00 74 00 20 00 68 00 6b 00 6c 00 6d 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_9 = {72 00 65 00 67 00 [0-10] 20 00 65 00 78 00 70 00 6f 00 72 00 74 00 20 00 68 00 6b 00 6c 00 6d 00 5c 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00}  //weight: 1, accuracy: Low
        $x_1_10 = {72 00 65 00 67 00 [0-10] 20 00 65 00 78 00 70 00 6f 00 72 00 74 00 20 00 68 00 6b 00 65 00 79 00 5f 00 6c 00 6f 00 63 00 61 00 6c 00 5f 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 73 00 61 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_11 = {72 00 65 00 67 00 [0-10] 20 00 65 00 78 00 70 00 6f 00 72 00 74 00 20 00 68 00 6b 00 65 00 79 00 5f 00 6c 00 6f 00 63 00 61 00 6c 00 5f 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_12 = {72 00 65 00 67 00 [0-10] 20 00 65 00 78 00 70 00 6f 00 72 00 74 00 20 00 68 00 6b 00 65 00 79 00 5f 00 6c 00 6f 00 63 00 61 00 6c 00 5f 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CredentialDumping_ZPB_2147934399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CredentialDumping.ZPB"
        threat_id = "2147934399"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CredentialDumping"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {65 00 73 00 65 00 6e 00 74 00 75 00 74 00 6c 00 02 00 0a 00 20 00 2f 00 79 00 20 00 2f 00 76 00 73 00 73 00}  //weight: 10, accuracy: Low
        $x_1_2 = "\\config\\SAM" wide //weight: 1
        $x_1_3 = "/config/SAM" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CredentialDumping_ZPC_2147934400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CredentialDumping.ZPC"
        threat_id = "2147934400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CredentialDumping"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "certutil" wide //weight: 1
        $x_1_2 = " -f " wide //weight: 1
        $x_1_3 = " -v " wide //weight: 1
        $x_1_4 = "-encodehex" wide //weight: 1
        $x_1_5 = "GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" wide //weight: 1
        $x_1_6 = "\\config\\SAM" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CredentialDumping_ZPD_2147934405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CredentialDumping.ZPD"
        threat_id = "2147934405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CredentialDumping"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 6b 00 65 00 79 00 [0-10] 20 00 2f 00 6c 00 69 00 73 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CredentialDumping_ZPE_2147934406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CredentialDumping.ZPE"
        threat_id = "2147934406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CredentialDumping"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lsadump::dcsync" wide //weight: 1
        $x_1_2 = "/domain" wide //weight: 1
        $x_1_3 = "/user" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CredentialDumping_ZPF_2147934407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CredentialDumping.ZPF"
        threat_id = "2147934407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CredentialDumping"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 00 73 00 65 00 63 00 64 00 75 00 6d 00 70 00 [0-10] 20 00 2d 00 61 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_MpTamperBlockSetFirewall_AE_2147773096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperBlockSetFirewall.AE"
        threat_id = "2147773096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperBlockSetFirewall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\system32\\windowspowershell\\v1.0\\powershell.exe" wide //weight: 2
        $x_2_2 = "set-netfirewallrule " wide //weight: 2
        $x_2_3 = {2d 00 73 00 65 00 72 00 [0-15] 77 00 69 00 6e 00 64 00 65 00 66 00 65 00 6e 00 64 00}  //weight: 2, accuracy: Low
        $x_1_4 = {2d 00 61 00 63 00 [0-15] 62 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2d 00 61 00 63 00 [0-15] 30 00}  //weight: 1, accuracy: Low
        $x_1_6 = "e245f2c5-db82-4b4e-9e04-c9ac8909c80e" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MpTamperBlockSetFirewall_B_2147773097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperBlockSetFirewall.B"
        threat_id = "2147773097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperBlockSetFirewall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\system32\\windowspowershell\\v1.0\\powershell.exe" wide //weight: 2
        $x_2_2 = "set-netfirewallrule " wide //weight: 2
        $x_2_3 = {2d 00 70 00 72 00 6f 00 67 00 [0-160] 6d 00 73 00 6d 00 70 00 65 00 6e 00 67 00 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_1_4 = {2d 00 61 00 63 00 [0-15] 62 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2d 00 61 00 63 00 [0-15] 30 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MpTamperBlockSetFirewall_B_2147773097_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperBlockSetFirewall.B"
        threat_id = "2147773097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperBlockSetFirewall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\system32\\windowspowershell\\v1.0\\powershell.exe" wide //weight: 2
        $x_2_2 = "set-netfirewallrule " wide //weight: 2
        $x_2_3 = {2d 00 70 00 72 00 6f 00 67 00 [0-160] 73 00 65 00 6e 00 73 00 65 00 63 00 6e 00 63 00 70 00 72 00 6f 00 78 00 79 00 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_1_4 = {2d 00 61 00 63 00 [0-15] 62 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2d 00 61 00 63 00 [0-15] 30 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MpTamperBlockSetFirewall_C_2147773098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperBlockSetFirewall.C"
        threat_id = "2147773098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperBlockSetFirewall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\system32\\windowspowershell\\v1.0\\powershell.exe" wide //weight: 2
        $x_2_2 = "set-netfirewallrule " wide //weight: 2
        $x_2_3 = {2d 00 70 00 72 00 6f 00 67 00 [0-160] 6d 00 73 00 73 00 65 00 6e 00 73 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_1_4 = {2d 00 61 00 63 00 [0-15] 62 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2d 00 61 00 63 00 [0-15] 30 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MpTamperBlockSetFirewall_D_2147773099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperBlockSetFirewall.D"
        threat_id = "2147773099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperBlockSetFirewall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\system32\\windowspowershell\\v1.0\\powershell.exe" wide //weight: 2
        $x_2_2 = "set-netfirewallrule " wide //weight: 2
        $x_2_3 = {2d 00 73 00 65 00 72 00 [0-15] 73 00 65 00 6e 00 73 00 65 00}  //weight: 2, accuracy: Low
        $x_1_4 = {2d 00 61 00 63 00 [0-15] 62 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2d 00 61 00 63 00 [0-15] 30 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MpTamperBlockSetFirewall_EE_2147773100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperBlockSetFirewall.EE"
        threat_id = "2147773100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperBlockSetFirewall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\system32\\windowspowershell\\v1.0\\powershell.exe" wide //weight: 2
        $x_2_2 = "set-netfirewallrule " wide //weight: 2
        $x_2_3 = {2d 00 70 00 72 00 6f 00 67 00 [0-160] 6d 00 73 00 6d 00 70 00 65 00 6e 00 67 00 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_1_4 = {2d 00 61 00 63 00 [0-15] 62 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2d 00 61 00 63 00 [0-15] 30 00}  //weight: 1, accuracy: Low
        $x_1_6 = "b45033f8-f2ba-4d9e-8263-e9ce79fbabca" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MpTamperBlockSetFirewall_A_2147773102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperBlockSetFirewall.A"
        threat_id = "2147773102"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperBlockSetFirewall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\system32\\windowspowershell\\v1.0\\powershell.exe" wide //weight: 2
        $x_2_2 = "set-netfirewallrule " wide //weight: 2
        $x_2_3 = {2d 00 73 00 65 00 72 00 [0-15] 77 00 69 00 6e 00 64 00 65 00 66 00 65 00 6e 00 64 00}  //weight: 2, accuracy: Low
        $x_1_4 = {2d 00 61 00 63 00 [0-15] 62 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2d 00 61 00 63 00 [0-15] 30 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


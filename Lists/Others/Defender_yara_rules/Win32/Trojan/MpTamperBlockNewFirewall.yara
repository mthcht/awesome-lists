rule Trojan_Win32_MpTamperBlockNewFirewall_AE_2147773091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperBlockNewFirewall.AE"
        threat_id = "2147773091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperBlockNewFirewall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\system32\\windowspowershell\\v1.0\\powershell.exe" wide //weight: 2
        $x_2_2 = "new-netfirewallrule " wide //weight: 2
        $x_2_3 = {2d 00 73 00 65 00 72 00 [0-15] 77 00 69 00 6e 00 64 00 65 00 66 00 65 00 6e 00 64 00}  //weight: 2, accuracy: Low
        $x_1_4 = {2d 00 61 00 63 00 [0-15] 62 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2d 00 61 00 63 00 [0-15] 30 00}  //weight: 1, accuracy: Low
        $x_1_6 = "86ea4d9c-2d5a-4818-880b-08e4f5ae7aee" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MpTamperBlockNewFirewall_B_2147773092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperBlockNewFirewall.B"
        threat_id = "2147773092"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperBlockNewFirewall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\system32\\windowspowershell\\v1.0\\powershell.exe" wide //weight: 2
        $x_2_2 = "new-netfirewallrule " wide //weight: 2
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

rule Trojan_Win32_MpTamperBlockNewFirewall_B_2147773092_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperBlockNewFirewall.B"
        threat_id = "2147773092"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperBlockNewFirewall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\system32\\windowspowershell\\v1.0\\powershell.exe" wide //weight: 2
        $x_2_2 = "new-netfirewallrule " wide //weight: 2
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

rule Trojan_Win32_MpTamperBlockNewFirewall_C_2147773093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperBlockNewFirewall.C"
        threat_id = "2147773093"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperBlockNewFirewall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\system32\\windowspowershell\\v1.0\\powershell.exe" wide //weight: 2
        $x_2_2 = "new-netfirewallrule " wide //weight: 2
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

rule Trojan_Win32_MpTamperBlockNewFirewall_D_2147773094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperBlockNewFirewall.D"
        threat_id = "2147773094"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperBlockNewFirewall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\system32\\windowspowershell\\v1.0\\powershell.exe" wide //weight: 2
        $x_2_2 = "new-netfirewallrule " wide //weight: 2
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

rule Trojan_Win32_MpTamperBlockNewFirewall_EE_2147773095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperBlockNewFirewall.EE"
        threat_id = "2147773095"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperBlockNewFirewall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\system32\\windowspowershell\\v1.0\\powershell.exe" wide //weight: 2
        $x_2_2 = "new-netfirewallrule " wide //weight: 2
        $x_2_3 = {2d 00 70 00 72 00 6f 00 67 00 [0-160] 6d 00 73 00 6d 00 70 00 65 00 6e 00 67 00 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_1_4 = {2d 00 61 00 63 00 [0-15] 62 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2d 00 61 00 63 00 [0-15] 30 00}  //weight: 1, accuracy: Low
        $x_1_6 = "326423b7-3fe4-4ed2-8dd2-34e1543dc89a" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MpTamperBlockNewFirewall_A_2147773101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperBlockNewFirewall.A"
        threat_id = "2147773101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperBlockNewFirewall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\system32\\windowspowershell\\v1.0\\powershell.exe" wide //weight: 2
        $x_2_2 = "new-netfirewallrule " wide //weight: 2
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


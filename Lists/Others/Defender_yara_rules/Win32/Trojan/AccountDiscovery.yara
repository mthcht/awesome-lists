rule Trojan_Win32_AccountDiscovery_B_2147768509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AccountDiscovery.B!net"
        threat_id = "2147768509"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AccountDiscovery"
        severity = "Critical"
        info = "net: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net accounts" wide //weight: 1
        $x_1_2 = "net.exe accounts" wide //weight: 1
        $x_1_3 = "net1 accounts" wide //weight: 1
        $x_1_4 = "net1.exe accounts" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_AccountDiscovery_A_2147768520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AccountDiscovery.A!net"
        threat_id = "2147768520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AccountDiscovery"
        severity = "Critical"
        info = "net: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "domain" wide //weight: 1
        $x_3_2 = {6e 00 65 00 74 00 20 00 [0-64] 75 00 73 00 65 00 72 00}  //weight: 3, accuracy: Low
        $x_3_3 = {6e 00 65 00 74 00 2e 00 65 00 78 00 65 00 [0-64] 75 00 73 00 65 00 72 00}  //weight: 3, accuracy: Low
        $x_3_4 = {6e 00 65 00 74 00 31 00 20 00 [0-64] 75 00 73 00 65 00 72 00}  //weight: 3, accuracy: Low
        $x_3_5 = {6e 00 65 00 74 00 31 00 2e 00 65 00 78 00 65 00 [0-64] 75 00 73 00 65 00 72 00}  //weight: 3, accuracy: Low
        $n_3_6 = "/delete" wide //weight: -3
        $n_3_7 = "/user" wide //weight: -3
        $n_3_8 = "-user" wide //weight: -3
        $n_3_9 = ".net" wide //weight: -3
        $n_3_10 = "\\user" wide //weight: -3
        $n_3_11 = "cmdkey" wide //weight: -3
        $n_3_12 = "never_match_this" wide //weight: -3
        $n_3_13 = "netuser.exe" wide //weight: -3
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AccountDiscovery_A_2147768521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AccountDiscovery.A!wmic"
        threat_id = "2147768521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AccountDiscovery"
        severity = "Critical"
        info = "wmic: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 00 6d 00 69 00 63 00 [0-64] 75 00 73 00 65 00 72 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = {67 00 65 00 74 00 2d 00 77 00 6d 00 69 00 6f 00 62 00 6a 00 65 00 63 00 74 00 [0-80] 77 00 69 00 6e 00 33 00 32 00 5f 00 75 00 73 00 65 00 72 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00}  //weight: 1, accuracy: Low
        $x_1_3 = {67 00 77 00 6d 00 69 00 20 00 [0-80] 77 00 69 00 6e 00 33 00 32 00 5f 00 75 00 73 00 65 00 72 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00}  //weight: 1, accuracy: Low
        $n_3_4 = "never_match_this" wide //weight: -3
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_AccountDiscovery_A_2147768521_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AccountDiscovery.A!wmic"
        threat_id = "2147768521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AccountDiscovery"
        severity = "Critical"
        info = "wmic: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 00 6d 00 69 00 63 00 [0-64] 75 00 73 00 65 00 72 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = {67 00 65 00 74 00 2d 00 77 00 6d 00 69 00 6f 00 62 00 6a 00 65 00 63 00 74 00 [0-80] 77 00 69 00 6e 00 33 00 32 00 5f 00 75 00 73 00 65 00 72 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00}  //weight: 1, accuracy: Low
        $x_1_3 = {67 00 77 00 6d 00 69 00 20 00 [0-80] 77 00 69 00 6e 00 33 00 32 00 5f 00 75 00 73 00 65 00 72 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_AccountDiscovery_E_2147768653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AccountDiscovery.E"
        threat_id = "2147768653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AccountDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmdkey" wide //weight: 1
        $x_1_2 = "vaultcmd" wide //weight: 1
        $n_1_3 = ".net" wide //weight: -1
        $n_1_4 = "/add" wide //weight: -1
        $n_1_5 = "/delete" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_AccountDiscovery_F_2147768654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AccountDiscovery.F"
        threat_id = "2147768654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AccountDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_2_2 = "get-localuser" wide //weight: 2
        $x_2_3 = "get-localgroup" wide //weight: 2
        $x_2_4 = "get-localgroupmember" wide //weight: 2
        $x_2_5 = "get-gporeport" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AccountDiscovery_G_2147768655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AccountDiscovery.G"
        threat_id = "2147768655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AccountDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dsquery.exe" wide //weight: 1
        $x_1_2 = "dsget.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


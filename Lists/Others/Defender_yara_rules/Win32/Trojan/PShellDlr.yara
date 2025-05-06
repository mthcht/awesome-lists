rule Trojan_Win32_PShellDlr_SB_2147838602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.SB"
        threat_id = "2147838602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = {6e 00 65 00 77 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 [0-32] 6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00}  //weight: 10, accuracy: Low
        $x_1_3 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 73 00 68 00 6f 00 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 78 00 79 00 7a 00}  //weight: 1, accuracy: Low
        $x_1_5 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 62 00 69 00 7a 00}  //weight: 1, accuracy: Low
        $x_1_6 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 63 00 79 00 6f 00 75 00}  //weight: 1, accuracy: Low
        $x_1_7 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 63 00 6c 00 69 00 63 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_8 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 6c 00 61 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PShellDlr_SB_2147838602_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.SB"
        threat_id = "2147838602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" ascii //weight: 1
        $x_1_2 = "new-object net.webclient" ascii //weight: 1
        $x_1_3 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-1] 3a 00 2f 00 2f 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 3a 00 29 08 08 00 2f 00 31 20 20 00 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6d 00 73 00 69 00 6d 00 61 00 6b 00 65 00 [0-16] 68 00 74 00 74 00 70 00 [0-1] 3a 00 2f 00 2f 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 2e 00 29 03 03 00 3a 00 29 08 08 00 2f 00 31 20 20 00 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PShellDlr_SA_2147848420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.SA"
        threat_id = "2147848420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" ascii //weight: 1
        $x_1_2 = "new-object net.webclient" ascii //weight: 1
        $x_1_3 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-1] 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PShellDlr_SC_2147931676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.SC"
        threat_id = "2147931676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "net.webclient" wide //weight: 10
        $x_10_3 = ").invoke(" wide //weight: 10
        $x_10_4 = ").value|foreach" wide //weight: 10
        $x_1_5 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 73 00 68 00 6f 00 70 00}  //weight: 1, accuracy: Low
        $x_1_6 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 78 00 79 00 7a 00}  //weight: 1, accuracy: Low
        $x_1_7 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 62 00 69 00 7a 00}  //weight: 1, accuracy: Low
        $x_1_8 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 63 00 79 00 6f 00 75 00}  //weight: 1, accuracy: Low
        $x_1_9 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 63 00 6c 00 69 00 63 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_10 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-48] 2e 00 6c 00 61 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PShellDlr_PA_2147934093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.PA!MTB"
        threat_id = "2147934093"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "New-NetFirewallRule -DisplayName" wide //weight: 1
        $x_1_3 = "Windows Update" wide //weight: 1
        $x_2_4 = {2d 00 52 00 65 00 6d 00 6f 00 74 00 65 00 41 00 64 00 64 00 72 00 65 00 73 00 73 00 20 00 [0-48] 20 00 2d 00 50 00 72 00 6f 00 74 00 6f 00 63 00 6f 00 6c 00 20 00 54 00 43 00 50 00 20 00 2d 00 41 00 63 00 74 00 69 00 6f 00 6e 00 20 00 41 00 6c 00 6c 00 6f 00 77 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PShellDlr_SF_2147937009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.SF!MTB"
        threat_id = "2147937009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1051"
        strings_accuracy = "High"
    strings:
        $x_500_1 = "powershell" wide //weight: 500
        $x_500_2 = "net.webclient" wide //weight: 500
        $x_50_3 = "invoke" wide //weight: 50
        $x_50_4 = "Create().AddScript(" wide //weight: 50
        $x_50_5 = " iwr" wide //weight: 50
        $x_1_6 = ".shop" wide //weight: 1
        $x_1_7 = ".xyz" wide //weight: 1
        $x_1_8 = ".cyou" wide //weight: 1
        $x_1_9 = ".click" wide //weight: 1
        $x_1_10 = ".online" wide //weight: 1
        $x_1_11 = ".today" wide //weight: 1
        $x_1_12 = ".lat" wide //weight: 1
        $x_1_13 = ".icu" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_500_*) and 1 of ($x_50_*) and 1 of ($x_1_*))) or
            ((2 of ($x_500_*) and 2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PShellDlr_SG_2147937656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.SG!MTB"
        threat_id = "2147937656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1110"
        strings_accuracy = "Low"
    strings:
        $x_500_1 = "powershell" wide //weight: 500
        $x_500_2 = "net.webclient" wide //weight: 500
        $x_10_3 = "invoke" wide //weight: 10
        $x_10_4 = "join" wide //weight: 10
        $x_100_5 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-60] 2e 00 73 00 68 00 6f 00 70 00}  //weight: 100, accuracy: Low
        $x_100_6 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-60] 2e 00 78 00 79 00 7a 00}  //weight: 100, accuracy: Low
        $x_100_7 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-60] 2e 00 63 00 79 00 6f 00 75 00}  //weight: 100, accuracy: Low
        $x_100_8 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-60] 2e 00 63 00 6c 00 69 00 63 00 6b 00}  //weight: 100, accuracy: Low
        $x_100_9 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-60] 2e 00 6c 00 61 00 74 00}  //weight: 100, accuracy: Low
        $x_100_10 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-60] 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00}  //weight: 100, accuracy: Low
        $x_100_11 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-60] 2e 00 74 00 6f 00 64 00 61 00 79 00}  //weight: 100, accuracy: Low
        $x_100_12 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-60] 2e 00 77 00 6f 00 72 00 6c 00 64 00}  //weight: 100, accuracy: Low
        $x_100_13 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-60] 2e 00 69 00 63 00 75 00}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_500_*) and 6 of ($x_100_*) and 1 of ($x_10_*))) or
            ((1 of ($x_500_*) and 7 of ($x_100_*))) or
            ((2 of ($x_500_*) and 1 of ($x_100_*) and 1 of ($x_10_*))) or
            ((2 of ($x_500_*) and 2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_PShellDlr_YH_2147939072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.YH!MTB"
        threat_id = "2147939072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = ".shop/" wide //weight: 100
        $x_100_2 = ".xyz/" wide //weight: 100
        $x_100_3 = ".today/" wide //weight: 100
        $x_100_4 = ".run/" wide //weight: 100
        $x_100_5 = ".cyou/" wide //weight: 100
        $x_100_6 = ".click/" wide //weight: 100
        $x_100_7 = ".lat/" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_PShellDlr_YM_2147939370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.YM!MTB"
        threat_id = "2147939370"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "-split" wide //weight: 10
        $x_10_2 = "char]([convert]::ToInt32($_" wide //weight: 10
        $x_10_3 = "powershell" wide //weight: 10
        $x_10_4 = "-join" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PShellDlr_HA_2147940742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.HA!MTB"
        threat_id = "2147940742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "56"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {28 00 6e 00 65 00 77 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 29 00 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 66 00 69 00 6c 00 65 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-60] 2e 00 65 00 78 00 65 00 27 00 2c 00 24 00 64 00 29 00 3b 00}  //weight: 50, accuracy: Low
        $x_5_2 = {2d 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 74 00 79 00 6c 00 65 00 20 00 68 00 69 00 64 00 64 00 65 00 6e 00 20 00 24 00 64 00 3d 00 24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 2b 00 27 00 [0-80] 2e 00 65 00 78 00 65 00 27 00 3b 00}  //weight: 5, accuracy: Low
        $x_1_3 = "start-process $d;" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


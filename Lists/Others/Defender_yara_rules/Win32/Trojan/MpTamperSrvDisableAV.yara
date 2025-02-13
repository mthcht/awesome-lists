rule Trojan_Win32_MpTamperSrvDisableAV_C_2147725443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperSrvDisableAV.C"
        threat_id = "2147725443"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperSrvDisableAV"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 [0-4] 74 00 72 00 75 00 73 00 74 00 65 00 64 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 20 00 [0-4] 62 00 69 00 6e 00 70 00 61 00 74 00 68 00 [0-2] 3d 00 [0-64] 77 00 69 00 6e 00 64 00 65 00 66 00 65 00 6e 00 64 00}  //weight: 1, accuracy: Low
        $x_1_2 = {63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 [0-4] 74 00 72 00 75 00 73 00 74 00 65 00 64 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 20 00 [0-4] 62 00 69 00 6e 00 70 00 61 00 74 00 68 00 [0-2] 3d 00 [0-64] 6d 00 73 00 73 00 65 00 6e 00 73 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 [0-4] 74 00 72 00 75 00 73 00 74 00 65 00 64 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 20 00 [0-4] 62 00 69 00 6e 00 70 00 61 00 74 00 68 00 [0-2] 3d 00 [0-64] 20 00 73 00 63 00 20 00 73 00 74 00 6f 00 70 00 20 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_MpTamperSrvDisableAV_D_2147752485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperSrvDisableAV.D"
        threat_id = "2147752485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperSrvDisableAV"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 00 63 00 20 00 73 00 74 00 6f 00 70 00 20 00 [0-4] 77 00 69 00 6e 00 64 00 65 00 66 00 65 00 6e 00 64 00}  //weight: 2, accuracy: Low
        $x_2_2 = {73 00 63 00 20 00 73 00 74 00 6f 00 70 00 20 00 [0-4] 77 00 64 00 66 00 69 00 6c 00 74 00 65 00 72 00}  //weight: 2, accuracy: Low
        $x_2_3 = {73 00 63 00 20 00 73 00 74 00 6f 00 70 00 20 00 [0-4] 73 00 65 00 6e 00 73 00 65 00}  //weight: 2, accuracy: Low
        $n_2_4 = "sense shield" wide //weight: -2
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_MpTamperSrvDisableAV_E_2147780715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperSrvDisableAV.E"
        threat_id = "2147780715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperSrvDisableAV"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "stop windefend" wide //weight: 2
        $x_2_2 = "stop wdfilter" wide //weight: 2
        $x_2_3 = "stop sense" wide //weight: 2
        $x_2_4 = "stop diagtrack" wide //weight: 2
        $n_2_5 = "sense shield" wide //weight: -2
        $x_1_6 = "u:t" wide //weight: 1
        $x_1_7 = "u=t" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MpTamperSrvDisableAV_E_2147780715_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperSrvDisableAV.E"
        threat_id = "2147780715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperSrvDisableAV"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 [0-4] 77 00 69 00 6e 00 64 00 65 00 66 00 65 00 6e 00 64 00 20 00 [0-4] 62 00 69 00 6e 00 70 00 61 00 74 00 68 00 [0-2] 3d 00}  //weight: 1, accuracy: Low
        $x_1_2 = {63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 [0-4] 77 00 64 00 66 00 69 00 6c 00 74 00 65 00 72 00 20 00 [0-4] 62 00 69 00 6e 00 70 00 61 00 74 00 68 00 [0-2] 3d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 [0-4] 73 00 65 00 6e 00 73 00 65 00 20 00 [0-4] 62 00 69 00 6e 00 70 00 61 00 74 00 68 00 [0-2] 3d 00}  //weight: 1, accuracy: Low
        $x_1_4 = {63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 [0-4] 64 00 69 00 61 00 67 00 74 00 72 00 61 00 63 00 6b 00 20 00 [0-4] 62 00 69 00 6e 00 70 00 61 00 74 00 68 00 [0-2] 3d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_MpTamperSrvDisableAV_F_2147780716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperSrvDisableAV.F"
        threat_id = "2147780716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperSrvDisableAV"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {63 00 6f 00 6e 00 66 00 69 00 67 00 [0-6] 74 00 72 00 75 00 73 00 74 00 65 00 64 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 [0-6] 62 00 69 00 6e 00 70 00 61 00 74 00 68 00}  //weight: 4, accuracy: Low
        $x_1_2 = {77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 [0-255] 73 00 65 00 6e 00 73 00 65 00 65 00 6e 00 61 00 62 00 6c 00 65 00 64 00}  //weight: 1, accuracy: Low
        $x_1_3 = {69 00 63 00 61 00 63 00 6c 00 73 00 [0-255] 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_4 = {69 00 63 00 61 00 63 00 6c 00 73 00 [0-255] 73 00 6d 00 61 00 72 00 74 00 73 00 63 00 72 00 65 00 65 00 6e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MpTamperSrvDisableAV_G_2147784134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperSrvDisableAV.G"
        threat_id = "2147784134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperSrvDisableAV"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "delete windefend" wide //weight: 2
        $x_2_2 = "delete wdfilter" wide //weight: 2
        $x_2_3 = "delete sense" wide //weight: 2
        $x_2_4 = "delete diagtrack" wide //weight: 2
        $n_2_5 = "sense shield" wide //weight: -2
        $x_1_6 = "u:t" wide //weight: 1
        $x_1_7 = "u=t" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MpTamperSrvDisableAV_H_2147785083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperSrvDisableAV.H"
        threat_id = "2147785083"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperSrvDisableAV"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "stop windefend" wide //weight: 2
        $x_2_2 = "delete windefend" wide //weight: 2
        $x_2_3 = "stop wdfilter" wide //weight: 2
        $x_2_4 = "delete wdfilter" wide //weight: 2
        $x_2_5 = "stop sense" wide //weight: 2
        $x_2_6 = "delete sense" wide //weight: 2
        $n_2_7 = "sense shield" wide //weight: -2
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_MpTamperSrvDisableAV_I_2147794155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperSrvDisableAV.I"
        threat_id = "2147794155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperSrvDisableAV"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Stop-Service WinDefend" wide //weight: 1
        $x_1_2 = "Stop-Service -Name WinDefend" wide //weight: 1
        $x_1_3 = "Stop-Service Microsoft Defender Antivirus Service" wide //weight: 1
        $x_1_4 = "Stop-Service -DisplayName Microsoft Defender Antivirus Service" wide //weight: 1
        $x_1_5 = "Get-Service WinDefend | Stop-Service" wide //weight: 1
        $x_1_6 = "Get-Service -Name WinDefend | Stop-Service" wide //weight: 1
        $x_1_7 = "Get-Service Microsoft Defender Antivirus Service | Stop-Service" wide //weight: 1
        $x_1_8 = "Get-Service -DisplayName Microsoft Defender Antivirus Service | Stop-Service" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_MpTamperSrvDisableAV_J_2147794156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperSrvDisableAV.J"
        threat_id = "2147794156"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperSrvDisableAV"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "WinDefend" wide //weight: 10
        $x_10_2 = "Microsoft Defender Antivirus Service" wide //weight: 10
        $x_1_3 = "Set-Service" wide //weight: 1
        $x_1_4 = "-StartupType Disabled" wide //weight: 1
        $x_1_5 = "-StartupType Manual" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MpTamperSrvDisableAV_K_2147794157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperSrvDisableAV.K"
        threat_id = "2147794157"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperSrvDisableAV"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 00 65 00 74 00 2d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 57 00 69 00 6e 00 44 00 65 00 66 00 65 00 6e 00 64 00 20 00 7c 00 20 00 53 00 65 00 74 00 2d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 [0-255] 2d 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 54 00 79 00 70 00 65 00 20 00 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 64 00 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = {47 00 65 00 74 00 2d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 2d 00 4e 00 61 00 6d 00 65 00 20 00 57 00 69 00 6e 00 44 00 65 00 66 00 65 00 6e 00 64 00 20 00 7c 00 20 00 53 00 65 00 74 00 2d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 [0-255] 2d 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 54 00 79 00 70 00 65 00 20 00 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 64 00}  //weight: 1, accuracy: Low
        $x_1_3 = {47 00 65 00 74 00 2d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 7c 00 20 00 53 00 65 00 74 00 2d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 [0-255] 2d 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 54 00 79 00 70 00 65 00 20 00 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 64 00}  //weight: 1, accuracy: Low
        $x_1_4 = {47 00 65 00 74 00 2d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 2d 00 44 00 69 00 73 00 70 00 6c 00 61 00 79 00 4e 00 61 00 6d 00 65 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 7c 00 20 00 53 00 65 00 74 00 2d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 [0-255] 2d 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 54 00 79 00 70 00 65 00 20 00 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 64 00}  //weight: 1, accuracy: Low
        $x_1_5 = {47 00 65 00 74 00 2d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 57 00 69 00 6e 00 44 00 65 00 66 00 65 00 6e 00 64 00 20 00 7c 00 20 00 53 00 65 00 74 00 2d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 [0-255] 2d 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 54 00 79 00 70 00 65 00 20 00 4d 00 61 00 6e 00 75 00 61 00 6c 00 20 00}  //weight: 1, accuracy: Low
        $x_1_6 = {47 00 65 00 74 00 2d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 2d 00 4e 00 61 00 6d 00 65 00 20 00 57 00 69 00 6e 00 44 00 65 00 66 00 65 00 6e 00 64 00 20 00 7c 00 20 00 53 00 65 00 74 00 2d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 [0-255] 2d 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 54 00 79 00 70 00 65 00 20 00 4d 00 61 00 6e 00 75 00 61 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_7 = {47 00 65 00 74 00 2d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 7c 00 20 00 53 00 65 00 74 00 2d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 [0-255] 2d 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 54 00 79 00 70 00 65 00 20 00 4d 00 61 00 6e 00 75 00 61 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_8 = {47 00 65 00 74 00 2d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 2d 00 44 00 69 00 73 00 70 00 6c 00 61 00 79 00 4e 00 61 00 6d 00 65 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 7c 00 20 00 53 00 65 00 74 00 2d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 [0-255] 2d 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 54 00 79 00 70 00 65 00 20 00 4d 00 61 00 6e 00 75 00 61 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


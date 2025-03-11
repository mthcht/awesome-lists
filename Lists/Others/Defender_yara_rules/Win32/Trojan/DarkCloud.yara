rule Trojan_Win32_DarkCloud_MBHP_2147852877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkCloud.MBHP!MTB"
        threat_id = "2147852877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d4 38 40 00 00 f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 80 35 40 00 40 35 40 00 c0 33 40 00 78 00 00 00 85 00 00 00 8e 00 00 00 8f}  //weight: 1, accuracy: High
        $x_1_2 = "svpaAfhWDOZhcfQttjAUreOpHTGCbHMhwWDQuwgeQPF" ascii //weight: 1
        $x_1_3 = "hvkLxKbCtVIhsSxYuBtRpFekZrFGjKZt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkCloud_MBIP_2147890349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkCloud.MBIP!MTB"
        threat_id = "2147890349"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 b5 4c 02 ce 82 e6 1d 87 19 44 52 33 d7 ec 1c 59 06 0e}  //weight: 1, accuracy: High
        $x_1_2 = {f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 ac 32 40 00 ac 32 40 00 2c 31 40 00 78 00 00 00 80 00 00 00 89}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkCloud_DA_2147897757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkCloud.DA!MTB"
        threat_id = "2147897757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 04 ab 91 e9 d1 5b 89 c1 c1 e9 18 31 c1 69 c1 91 e9 d1 5b 69 f6 91 e9 d1 5b 31 c6 45 39 ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkCloud_GZA_2147901776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkCloud.GZA!MTB"
        threat_id = "2147901776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d0 8d 4d ?? ff d6 ba ?? ?? ?? ?? 8d 4d 94 ff d7 8b 55 ?? 89 5d ?? 8d 4d 98 ff d6 8d 4d 94 51 8d 55 98 52}  //weight: 10, accuracy: Low
        $x_1_2 = "ChromeMetaMaskVaultData.txt" ascii //weight: 1
        $x_1_3 = "DARKCLOUD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkCloud_AZKA_2147933124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkCloud.AZKA!MTB"
        threat_id = "2147933124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-30] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-30] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_2_3 = {44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 22 00 20 00 2c 00 20 00 22 00 70 00 74 00 72 00 22 00 20 00 2c 00 20 00 22 00 56 00 69 00 72 00 74 00 22 00 20 00 26 00 20 00 22 00 75 00 61 00 6c 00 22 00 20 00 26 00 20 00 22 00 41 00 6c 00 6c 00 22 00 20 00 26 00 20 00 22 00 6f 00 63 00 22 00 20 00 2c 00 20 00 22 00 64 00 77 00 6f 00 72 00 64 00 22 00 20 00 2c 00 20 00 22 00 30 00 22 00 20 00 2c 00 20 00 22 00 64 00 77 00 6f 00 72 00 64 00 22 00 20 00 2c 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-30] 20 00 29 00 20 00 2c 00}  //weight: 2, accuracy: Low
        $x_2_4 = {44 4c 4c 43 41 4c 4c 20 28 20 22 6b 65 72 6e 65 6c 33 32 22 20 2c 20 22 70 74 72 22 20 2c 20 22 56 69 72 74 22 20 26 20 22 75 61 6c 22 20 26 20 22 41 6c 6c 22 20 26 20 22 6f 63 22 20 2c 20 22 64 77 6f 72 64 22 20 2c 20 22 30 22 20 2c 20 22 64 77 6f 72 64 22 20 2c 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-30] 20 29 20 2c}  //weight: 2, accuracy: Low
        $x_2_5 = "\"dword\" , \"0x\" & \"300\" & \"0\" , \"dword\" , \"0\" & \"x4\" & \"0\" )" ascii //weight: 2
        $x_2_6 = {44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 41 00 44 00 44 00 52 00 45 00 53 00 53 00 20 00 28 00 20 00 22 00 69 00 6e 00 74 00 22 00 20 00 2c 00 20 00 24 00 [0-30] 20 00 2b 00 20 00 39 00 31 00 33 00 36 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_7 = {44 4c 4c 43 41 4c 4c 41 44 44 52 45 53 53 20 28 20 22 69 6e 74 22 20 2c 20 24 [0-30] 20 2b 20 39 31 33 36 20 29}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_DarkCloud_AKLA_2147933549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkCloud.AKLA!MTB"
        threat_id = "2147933549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR &" ascii //weight: 1
        $x_2_2 = "D725984265l725984265l725984265Ca725984265ll" ascii //weight: 2
        $x_2_3 = "k725984265er725984265nel37259842652" ascii //weight: 2
        $x_2_4 = "725984265V725984265ir725984265tualA725984265llo725984265c" ascii //weight: 2
        $x_2_5 = "Ca725984265llWi725984265ndo725984265wPro725984265c" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DarkCloud_EALN_2147935744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkCloud.EALN!MTB"
        threat_id = "2147935744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 48 0c 8b 85 28 ff ff ff 8b b5 20 ff ff ff 8a 14 02 32 14 31 8b 45 cc 8b 48 0c 8b 85 18 ff ff ff 88 14 01 c7 45 fc 0b 00 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


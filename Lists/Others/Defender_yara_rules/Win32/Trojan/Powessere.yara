rule Trojan_Win32_Powessere_A_2147688591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.A"
        threat_id = "2147688591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "javascript:\"\\..\\mshtml,RunHTMLApplication \";eval" wide //weight: 1
        $x_1_2 = "aid=%s&builddate=%s&id=%s&os=%s_" ascii //weight: 1
        $x_1_3 = "iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('{loader}')))\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Powessere_A_2147688591_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.A"
        threat_id = "2147688591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 6b 58 6a 65 66 89 45 ?? 58 6a 72 66 89 45 ?? 58 6a 6e 66 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = {56 69 72 74 c7 45 ?? 75 61 6c 41 c7 45 ?? 6c 6c 6f 63 c6 45}  //weight: 1, accuracy: Low
        $x_2_3 = {8a 04 07 32 45 ff b1 08 2a cb 8a d0 d2 ea 8b cb d2 e0 0a d0 88 54 3e 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Powessere_A_2147688591_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.A"
        threat_id = "2147688591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 6b 58 6a 65 66 89 45 ?? 58 6a 72 66 89 45 ?? 58 6a 6e 66 89 45 ?? 58 6a 65 66 89 45 ?? 58 6a 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {32 45 ff b1 08 2a cb 8a d0 d2 ea 8b cb d2 e0 0a d0 88 54 3e 01 ff 45 f8 fe 45 ff 8b 45 f8 fe 45 fe 3b 45 0c 72}  //weight: 1, accuracy: High
        $x_1_3 = "=cmd_%u&version=" ascii //weight: 1
        $x_1_4 = "=debug_um3_%s&version=" ascii //weight: 1
        $x_1_5 = "reinstok" ascii //weight: 1
        $x_1_6 = "%[^;];%[^;];%[^;];%[^;];%s" ascii //weight: 1
        $x_1_7 = "egpname_%x_%x" ascii //weight: 1
        $x_1_8 = {3a 2f 2f 25 73 2f 71 00 73 6f 66 74 77 61 72 65 5c 63 6c 61 73 73 65 73 5c 63 6c 73 69 64 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Powessere_A_2147690012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.A!!Powessere.D"
        threat_id = "2147690012"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        info = "Powessere: an internal category used to refer to some threats"
        info = "D: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "javascript:\"\\..\\mshtml,RunHTMLApplication \";eval" wide //weight: 1
        $x_1_2 = "aid=%s&builddate=%s&id=%s&os=%s_" ascii //weight: 1
        $x_1_3 = "iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('{loader}')))\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Powessere_A_2147690012_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.A!!Powessere.D"
        threat_id = "2147690012"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        info = "Powessere: an internal category used to refer to some threats"
        info = "D: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 6b 58 6a 65 66 89 45 ?? 58 6a 72 66 89 45 ?? 58 6a 6e 66 89 45 ?? 58 6a 65 66 89 45 ?? 58 6a 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {32 45 ff b1 08 2a cb 8a d0 d2 ea 8b cb d2 e0 0a d0 88 54 3e 01 ff 45 f8 fe 45 ff 8b 45 f8 fe 45 fe 3b 45 0c 72}  //weight: 1, accuracy: High
        $x_1_3 = "=cmd_%u&version=" ascii //weight: 1
        $x_1_4 = "=debug_um3_%s&version=" ascii //weight: 1
        $x_1_5 = "reinstok" ascii //weight: 1
        $x_1_6 = "%[^;];%[^;];%[^;];%[^;];%s" ascii //weight: 1
        $x_1_7 = "egpname_%x_%x" ascii //weight: 1
        $x_1_8 = {3a 2f 2f 25 73 2f 71 00 73 6f 66 74 77 61 72 65 5c 63 6c 61 73 73 65 73 5c 63 6c 73 69 64 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Powessere_A_2147690012_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.A!!Powessere.D"
        threat_id = "2147690012"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        info = "Powessere: an internal category used to refer to some threats"
        info = "D: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5b f7 f3 83 fa 0a 72 03 83 c2 27 80 c2 30 88 94 3d f0 fe ff ff 47 3b fe 72 ce}  //weight: 2, accuracy: High
        $x_3_2 = {69 d2 04 01 00 00 81 c2 ?? ?? ?? ?? 52 57 ff 15 ?? ?? ?? ?? 83 c4 0c e8 ?? ?? ?? ?? 85 c0 75 16 68 60 ea 00 00 ff d5 43 83 fb 03 72 bb 68 c0 27 09 00 ff d5 eb b0}  //weight: 3, accuracy: Low
        $x_2_3 = {61 00 69 00 64 00 3a 00 20 00 25 00 53 00 0d 00 0a 00 62 00 75 00 69 00 6c 00 64 00 64 00 61 00 74 00 65 00 3a 00 20 00 25 00 53 00 0d 00 0a 00 70 00 69 00 64 00 3a 00 20 00 25 00 78 00}  //weight: 2, accuracy: High
        $x_2_4 = "-khb747bjg324yu" wide //weight: 2
        $x_1_5 = "<clickurl>" ascii //weight: 1
        $x_1_6 = "{server}/query?version=" ascii //weight: 1
        $x_1_7 = "builddate={builddate}" ascii //weight: 1
        $x_1_8 = "wt={threads}" ascii //weight: 1
        $x_1_9 = "lr={lastresult}" ascii //weight: 1
        $x_1_10 = "ls={laststage}" ascii //weight: 1
        $x_1_11 = "%[^;];%[^;];%[^;];%*[^;];%*[^;];%u" ascii //weight: 1
        $x_1_12 = "%*[^;];%*[^;];%*[^;];%*[^;];%u" ascii //weight: 1
        $x_2_13 = "degenerative+joint+disease" ascii //weight: 2
        $x_2_14 = "anti+aging+skin+care" ascii //weight: 2
        $x_2_15 = "online+auto+insurance+quotes" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Powessere_A_2147690012_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.A!!Powessere.D"
        threat_id = "2147690012"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        info = "Powessere: an internal category used to refer to some threats"
        info = "D: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 6b 58 6a 65 66 89 45 ?? 58 6a 72 66 89 45 ?? 58 6a 6e 66 89 45 ?? 58 6a 65 66 89 45 ?? 58 6a 6c 66 89 45 ?? 58 6a 33 66 89 45 ?? 58 6a 32}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 6f 61 64 c7 45 ?? 4c 69 62 72 c7 45 ?? 61 72 79 41 c6 45 ?? 00 c7 45 ?? 47 65 74 50 c7 45 ?? 72 6f 63 41 c7 45 ?? 64 64 72 65}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 55 f0 8b 75 08 8b 9e ?? ?? 00 00 81 c6 ?? ?? 00 00 6a 40 68 00 30 00 00 03 de}  //weight: 1, accuracy: Low
        $x_2_4 = "&aid=%s&builddate=%s&id=%s&os=%s_%s" ascii //weight: 2
        $x_1_5 = "%[^;];%[^;];%[^;];%[^;];%s" ascii //weight: 1
        $x_2_6 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 22 00 5c 00 2e 00 2e 00 5c 00 6d 00 73 00 68 00 74 00 6d 00 6c 00 [0-4] 2c 00 52 00 75 00 6e 00 48 00 54 00 4d 00 4c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 2, accuracy: Low
        $x_2_7 = {6a 61 76 61 73 63 72 69 70 74 3a 22 5c 2e 2e 5c 6d 73 68 74 6d 6c [0-4] 2c 52 75 6e 48 54 4d 4c 41 70 70 6c 69 63 61 74 69 6f 6e}  //weight: 2, accuracy: Low
        $x_1_8 = "{73E709EA-5D93-4B2E-BBB0-99B7938DA9E4}" ascii //weight: 1
        $x_1_9 = "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" ascii //weight: 1
        $x_1_10 = {eb 15 8d 85 ?? ?? ff ff 50 ff 14 f5 ?? ?? ?? ?? 85 c0 74 03 33 db 43 8d 77 01 85 ff 75}  //weight: 1, accuracy: Low
        $x_4_11 = {eb 02 33 ff ff 74 24 10 ff 15 ?? ?? ?? ?? 3b fe 75 10 68 88 13 00 00 ff 15 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? c7 44 24 14 ?? ?? ?? ?? 8b 44 24 14 8b 00 b9 ?? ?? ?? ?? 83 f8 05 74 05 b9 ?? ?? ?? ?? 56 8d 54 24 14 52 56 68 3f 01 0f 00}  //weight: 4, accuracy: Low
        $n_10_12 = "\\Adlice\\RogueKiller" ascii //weight: -10
        $n_10_13 = "SignatureBlacklistRulePoweliks" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Powessere_B_2147690913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.B"
        threat_id = "2147690913"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4b 43 89 d8 03 45 f8 8b 00 3d 68 74 74 70 75}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 e4 8b 10 81 fa 50 4f 53 54 75}  //weight: 1, accuracy: High
        $x_1_3 = {52 63 34 45 6e 63 6f 64 65 64 36 34 00 52 63 34 45 6e 63 6f 64 65 64 33 32 00 4a 61 76 61 53 63 72 69 70 74 00 43 6f 6d 6d 75 6e 69 63 61 74 65 00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 6a 61 76 61 73 63 72 69 70 74 3a 22 5c 2e 2e 5c 6d 73 68 74 6d 6c 2c 52 75 6e 48 54 4d 4c 41 70 70 6c 69 63 61 74 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_4 = {52 63 34 45 6e 63 6f 64 65 64 36 34 00 52 63 34 45 6e 63 6f 64 65 64 33 32 00 4a 61 76 61 53 63 72 69 70 74 00 43 6f 6d 6d 75 6e 69 63 61 74 65 00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 76 62 73 63 72 69 70 74 3a 22 5c 2e 2e 5c 6d 73 68 74 6d 6c 2c 52 75 6e 48 54 4d 4c 41 70 70 6c 69 63 61 74 69 6f 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Powessere_G_2147725444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.G"
        threat_id = "2147725444"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-48] 6d 00 73 00 68 00 74 00 6d 00 6c 00 2c 00 72 00 75 00 6e 00 68 00 74 00 6d 00 6c 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-48] 6d 00 73 00 68 00 74 00 6d 00 6c 00 2c 00 72 00 75 00 6e 00 68 00 74 00 6d 00 6c 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Powessere_G_2147725444_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.G"
        threat_id = "2147725444"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-48] 6d 00 73 00 68 00 74 00 6d 00 6c 00 [0-32] 72 00 75 00 6e 00 68 00 74 00 6d 00 6c 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-48] 6d 00 73 00 68 00 74 00 6d 00 6c 00 [0-32] 72 00 75 00 6e 00 68 00 74 00 6d 00 6c 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Powessere_G_2147725444_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.G"
        threat_id = "2147725444"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {5c 00 2e 00 2e 00 [0-2] 5c 00 6d 00 73 00 68 00 74 00 6d 00 6c 00 2c 00 52 00 75 00 6e 00 48 00 54 00 4d 00 4c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00}  //weight: 2, accuracy: Low
        $x_1_3 = {20 00 6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-32] 5c 00 2e 00 2e 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {20 00 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-32] 5c 00 2e 00 2e 00 5c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Powessere_H_2147726088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.H"
        threat_id = "2147726088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mshta" wide //weight: 1
        $x_1_2 = {41 00 63 00 74 00 69 00 76 00 65 00 58 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 22 00 57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 22 00 29 00 3b 00 [0-32] 3d 00 22 00 [0-32] 22 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 22 00 48 00 4b 00 43 00 55 00 5c 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 [0-32] 5c 00 5c 00 [0-32] 22 00 29 00 3b 00 [0-32] 3d 00 22 00 [0-32] 22 00 3b 00 65 00 76 00 61 00 6c 00 28 00 [0-32] 29 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 22 00 48 00 4b 00 43 00 55 00 5c 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 [0-32] 5c 00 5c 00 [0-32] 22 00 29 00 3b 00 [0-32] 3d 00 22 00 [0-32] 22 00 3b 00 74 00 68 00 69 00 73 00 5b 00 27 00 65 00 76 00 27 00 2b 00 27 00 61 00 6c 00 27 00 5d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Powessere_H_2147726088_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.H"
        threat_id = "2147726088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta" wide //weight: 1
        $x_1_2 = "about:<hta:application><script>" wide //weight: 1
        $x_1_3 = "resizeTo(1,1)" wide //weight: 1
        $x_1_4 = "eval(new ActiveXObject('WScript.Shell').RegRead('HKCU\\\\Software\\\\AppDataLow\\\\Software\\\\Microsoft\\\\" wide //weight: 1
        $x_1_5 = "if(!window.flag)close()" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Powessere_H_2147726088_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.H"
        threat_id = "2147726088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mshta" wide //weight: 1
        $x_1_2 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-16] 3d 00 27 00 27 00 3b 00 74 00 72 00 79 00 7b 00 74 00 68 00 72 00 6f 00 77 00 20 00 6e 00 65 00 77 00 20 00 45 00 72 00 72 00 6f 00 72 00 28 00 27 00 [0-32] 27 00 29 00 3b 00 7d 00 63 00 61 00 74 00 63 00 68 00 28 00 65 00 72 00 72 00 29 00 7b 00 [0-16] 3d 00 65 00 72 00 72 00 2e 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00 3b 00 7d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 00 6e 00 65 00 77 00 20 00 41 00 63 00 74 00 69 00 76 00 65 00 58 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 27 00 57 00 [0-48] 29 00 3b 00 [0-16] 3d 00 27 00 27 00 3b 00 [0-16] 3d 00 27 00 5c 00 5c 00 [0-32] 5c 00 5c 00 [0-32] 27 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 27 00 48 00 4b 00 4c 00 4d 00 5c 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 57 00 6f 00 77 00 36 00 34 00 33 00 32 00 4e 00 6f 00 64 00 65 00 27 00 2b 00 [0-16] 29 00 3b 00 7d 00 63 00 61 00 74 00 63 00 68 00 28 00 [0-16] 29 00 7b 00 7d 00 74 00 72 00 79 00 7b 00 69 00 66 00 28 00 [0-16] 29 00 65 00 76 00 61 00 6c 00 28 00 [0-16] 29 00 3b 00 7d 00 63 00 61 00 74 00 63 00 68 00 28 00 [0-16] 29 00 7b 00 7d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Powessere_H_2147726088_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.H"
        threat_id = "2147726088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\mshta.exe" wide //weight: 1
        $x_1_2 = {41 00 63 00 74 00 69 00 76 00 65 00 58 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 29 00 3b 00 [0-32] 3d 00 [0-32] 3b 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 48 00 4b 00 43 00 55 00 5c 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 [0-32] 5c 00 5c 00 [0-32] 29 00 3b 00 [0-32] 3d 00 [0-32] 3b 00 74 00 68 00 69 00 73 00 5b 00 27 00 65 00 76 00 27 00 2b 00 27 00 61 00 6c 00 27 00 5d 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 48 00 4b 00 43 00 55 00 5c 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 [0-32] 5c 00 5c 00 [0-32] 29 00 3b 00 [0-32] 3d 00 [0-32] 3b 00 65 00 76 00 61 00 6c 00 28 00 [0-32] 29 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 48 00 4b 00 4c 00 4d 00 5c 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 57 00 6f 00 77 00 36 00 34 00 33 00 32 00 4e 00 6f 00 64 00 65 00 5c 00 5c 00 [0-32] 5c 00 5c 00 [0-32] 29 00 3b 00 [0-32] 3d 00 [0-32] 3b 00 65 00 76 00 61 00 6c 00 28 00 [0-32] 29 00 3b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Powessere_I_2147726501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.I"
        threat_id = "2147726501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 [0-32] 5c 00 [0-32] 2e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-32] 3d 00 22 00 [0-32] 22 00 3b 00 [0-32] 3d 00 6e 00 65 00 77 00 20 00 41 00 63 00 74 00 69 00 76 00 65 00 58 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 22 00 57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 22 00 29 00 3b 00 [0-32] 3d 00 22 00 [0-32] 22 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 22 00 48 00 4b 00 43 00 55 00 5c 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 [0-32] 5c 00 5c 00 [0-32] 22 00 29 00 3b 00 [0-32] 3d 00 22 00 [0-32] 22 00 3b 00 65 00 76 00 61 00 6c 00 28 00 [0-32] 29 00 3b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Powessere_I_2147726501_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.I"
        threat_id = "2147726501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "Invoke-Expression ([System.Text.Encoding]::ASCII.GetString((Get-ItemProperty HKCU:Software\\AppDataLow\\Software\\Microsoft\\" wide //weight: 1
        $x_1_3 = {29 00 2e 00 [0-32] 29 00 29 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Powessere_K_2147734747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.K"
        threat_id = "2147734747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_2_2 = "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\\Software\\" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Powessere_K_2147734747_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.K"
        threat_id = "2147734747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "$(gP -Pa HKLM:\\SY" wide //weight: 1
        $x_1_3 = "iex $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64string($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Powessere_K_2147734747_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.K"
        threat_id = "2147734747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\powershell.exe" wide //weight: 1
        $x_2_2 = {69 00 65 00 78 00 28 00 5b 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 54 00 65 00 78 00 74 00 2e 00 45 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 41 00 53 00 43 00 49 00 49 00 2e 00 47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 28 00 47 00 65 00 74 00 2d 00 49 00 74 00 65 00 6d 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 79 00 20 00 27 00 48 00 4b 00 43 00 55 00 3a 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 4c 00 6f 00 77 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 27 00 29 00 2e 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 29 00 29 00}  //weight: 2, accuracy: Low
        $x_2_3 = {69 00 65 00 78 00 20 00 [0-2] 28 00 5b 00 54 00 65 00 78 00 74 00 2e 00 45 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 55 00 6e 00 69 00 63 00 6f 00 64 00 65 00 2e 00 47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 5b 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 28 00 47 00 65 00 74 00 2d 00 49 00 74 00 65 00 6d 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 79 00 20 00 2d 00 50 00 61 00 74 00 68 00 20 00 [0-2] 48 00 4b 00 4c 00 4d 00 3a 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 [0-32] 20 00 2d 00 4e 00 61 00 6d 00 65 00 20 00 [0-32] 29 00 2e 00 [0-32] 29 00 29 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {69 00 65 00 78 00 20 00 28 00 5b 00 54 00 65 00 78 00 74 00 2e 00 45 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 41 00 53 00 43 00 49 00 49 00 2e 00 47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 5b 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 28 00 67 00 70 00 20 00 [0-2] 48 00 4b 00 ?? ?? ?? ?? 3a 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 [0-64] 29 00 2e 00 [0-32] 29 00 29 00 29 00}  //weight: 2, accuracy: Low
        $x_2_5 = {24 00 74 00 3d 00 47 00 65 00 74 00 2d 00 49 00 74 00 65 00 6d 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 79 00 20 00 2d 00 50 00 61 00 74 00 68 00 20 00 27 00 48 00 4b 00 43 00 55 00 3a 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00 [0-32] 27 00 20 00 2d 00 4e 00 61 00 6d 00 65 00 20 00 74 00 3b 00 49 00 45 00 58 00 20 00 24 00 74 00 2e 00 74 00}  //weight: 2, accuracy: Low
        $x_2_6 = {49 00 65 00 78 00 20 00 24 00 28 00 5b 00 54 00 65 00 78 00 74 00 2e 00 45 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 55 00 6e 00 69 00 63 00 6f 00 64 00 65 00 2e 00 47 00 65 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-2] 5b 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 24 00 28 00 67 00 70 00 20 00 [0-8] 48 00 4b 00 [0-4] 3a 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 [0-64] 29 00 2e 00 [0-32] 29 00 29 00 29 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Powessere_L_2147735903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.L"
        threat_id = "2147735903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $n_10_1 = "mshta.exe" wide //weight: -10
        $x_1_2 = "\\cmd.exe" wide //weight: 1
        $x_1_3 = " /c start " wide //weight: 1
        $x_1_4 = "\\AppData\\Local\\" wide //weight: 1
        $x_1_5 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-32] 3d 00 [0-32] 3b 00}  //weight: 1, accuracy: Low
        $x_1_6 = "=new ActiveXObject(WScript.Shell);" wide //weight: 1
        $x_1_7 = {2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 48 00 4b 00 43 00 55 00 5c 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 [0-32] 5c 00 5c 00 [0-32] 29 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_8 = {3b 00 65 00 76 00 61 00 6c 00 28 00 [0-32] 29 00 3b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_Powessere_M_2147740997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.M"
        threat_id = "2147740997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "(Get-ItemProperty" wide //weight: 1
        $x_1_3 = {72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 3a 00 3a 00 48 00 4b 00 ?? ?? ?? ?? 5c 00 5c 00 53 00 3f 00 3f 00 3f 00 77 00 61 00 72 00 65 00 5c 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_4 = "iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Powessere_N_2147770116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.N"
        threat_id = "2147770116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\powershell.exe" wide //weight: 1
        $x_1_2 = "get-itemproperty -path 'HK" wide //weight: 1
        $x_1_3 = "[Byte]::Parse($" wide //weight: 1
        $x_1_4 = "]::HexNumber" wide //weight: 1
        $x_1_5 = "]::GetDomain().Load($" wide //weight: 1
        $x_1_6 = ".EntryPoint.invoke($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Powessere_O_2147772335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.O"
        threat_id = "2147772335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "javascript:" wide //weight: 1
        $x_1_3 = "ActiveXObject(" wide //weight: 1
        $x_1_4 = "wscript.shell" wide //weight: 1
        $x_1_5 = {2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 48 00 4b 00 43 00 55 00 5c 00 [0-4] 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_6 = ";eval(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Powessere_P_2147775263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.P"
        threat_id = "2147775263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {28 00 28 00 67 00 70 00 20 00 48 00 4b 00 43 00 55 00 3a 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 29 00 2e 00 [0-32] 29 00 7c 00 49 00 45 00 58 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Powessere_Q_2147775271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.Q"
        threat_id = "2147775271"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mshta" wide //weight: 1
        $x_1_2 = "vbscript:Execute" wide //weight: 1
        $x_1_3 = ").Run" wide //weight: 1
        $x_1_4 = "powershell" wide //weight: 1
        $x_1_5 = "Invoke-Expression" wide //weight: 1
        $x_1_6 = "iwr -uri " wide //weight: 1
        $x_1_7 = {2e 00 70 00 68 00 70 00 20 00 2d 00 6d 00 65 00 74 00 68 00 6f 00 64 00 20 00 70 00 6f 00 73 00 74 00 20 00 2d 00 62 00 6f 00 64 00 79 00 20 00 [0-32] 29 00 2e 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Powessere_S_2147793327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.S"
        threat_id = "2147793327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "/Create" wide //weight: 1
        $x_1_3 = "powershell" wide //weight: 1
        $x_1_4 = "::FromBase64String(" wide //weight: 1
        $x_1_5 = {28 00 67 00 70 00 20 00 [0-2] 48 00 4b 00 ?? ?? ?? ?? 3a 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Powessere_2147810190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.dll!attk"
        threat_id = "2147810190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-64] 6d 00 73 00 68 00 74 00 6d 00 6c 00 2c 00 72 00 75 00 6e 00 68 00 74 00 6d 00 6c 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-64] 6d 00 73 00 68 00 74 00 6d 00 6c 00 2c 00 72 00 75 00 6e 00 68 00 74 00 6d 00 6c 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Powessere_SA_2147817497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.SA"
        threat_id = "2147817497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "415"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "powershell.exe" wide //weight: 100
        $x_100_2 = "[system.text.encoding]::ascii.getstring" wide //weight: 100
        $x_100_3 = {68 00 6b 00 [0-4] 3a 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 [0-32] 29 00 2e 00 [0-32] 29 00}  //weight: 100, accuracy: Low
        $x_100_4 = "[system.convert]::frombase64string" wide //weight: 100
        $x_10_5 = "iex" wide //weight: 10
        $x_10_6 = "invoke-expression" wide //weight: 10
        $x_5_7 = "get-itemproperty " wide //weight: 5
        $x_5_8 = "gp " wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((4 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Powessere_X_2147831330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.X"
        threat_id = "2147831330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-48] 6d 00 73 00 68 00 74 00 6d 00 6c 00 2c 00 23 00 31 00 33 00 35 00}  //weight: 10, accuracy: Low
        $x_10_2 = {76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-48] 6d 00 73 00 68 00 74 00 6d 00 6c 00 2c 00 23 00 31 00 33 00 35 00}  //weight: 10, accuracy: Low
        $x_1_3 = "wscript.shell" wide //weight: 1
        $x_1_4 = ".run(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Powessere_T_2147958624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.T"
        threat_id = "2147958624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = ").GetValue(" wide //weight: 2
        $x_2_3 = ")).EntryPoint.Invoke(" wide //weight: 2
        $x_1_4 = ".OpenSubKey(" wide //weight: 1
        $x_1_5 = "get-item -Path" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


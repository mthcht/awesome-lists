rule Trojan_Win32_Astaroth_A_2147740064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.A!!Astaroth.A"
        threat_id = "2147740064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        info = "Astaroth: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 5c 38 ff 33 5d e4 8b 55 f0 8b c3 e8 ?? ?? ?? ?? 8b d8 8d 45 d4 8b d3 e8 ?? ?? ?? ?? 8b 55 d4 8d 45 ec e8 ?? ?? ?? ?? 8b 45 e4 89 45 f0 83 c6 02 8b 45 fc e8 ?? ?? ?? ?? 3b f0 7c 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Astaroth_A_2147745659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.A"
        threat_id = "2147745659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "cmd.exe" wide //weight: 5
        $x_5_2 = {2e 00 6a 00 73 00 7c 00 63 00 61 00 6c 00 6c 00 20 00 25 00 ?? ?? ?? ?? ?? ?? 3a 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3d 00 25 00}  //weight: 5, accuracy: Low
        $x_5_3 = ".js|exit" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Astaroth_B_2147745660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.B"
        threat_id = "2147745660"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "cmd" wide //weight: 5
        $x_10_2 = {74 00 79 00 70 00 65 00 20 00 [0-40] 2e 00 64 00 6c 00 6c 00 20 00 [0-40] 2e 00 64 00 6c 00 6c 00}  //weight: 10, accuracy: Low
        $x_1_3 = "mozcrt19.dll" wide //weight: 1
        $x_1_4 = "mozsqlite3.dll" wide //weight: 1
        $x_1_5 = "sqlite3.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Astaroth_C_2147745661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.C"
        threat_id = "2147745661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "cmd" wide //weight: 5
        $x_5_2 = "Internet Explorer" wide //weight: 5
        $x_5_3 = "ExtExport.exe" wide //weight: 5
        $x_5_4 = "\\Users\\Public\\Libraries\\" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Astaroth_2147836141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.psyA!MTB"
        threat_id = "2147836141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        info = "psyA: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {00 42 ae bf 21 06 cf d1 72 06 cf d1 72 06 cf d1 72 b2 53 20 72 15 cf d1 72 b2 53 22 72 a1 cf d1 72 b2 53 23 72 18 cf d1 72 0f b7 55 72 07 cf d1 72 98 6f 16 72 04 cf d1 72 ab 91 d2 73 1c cf d1 72 ab 91 d4 73 3c cf d1 72 ab 91 d5 73 24 cf d1 [0-48] 2e 72 07 cf d1 72 b3 91 d3 73 07 cf d1 72 52 69}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Astaroth_2147839281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.psyF!MTB"
        threat_id = "2147839281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        info = "psyF: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {8b 7d bc b9 14 00 00 00 b8 44 00 00 00 57 ab 33 c0 ab e2 fd 8b 7d b8}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Astaroth_2147839282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.psyM!MTB"
        threat_id = "2147839282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        info = "psyM: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {74 28 8b 45 08 03 45 0c 48 89 45 fc 8b 7d fc eb 14 8a 07 50 ff 75 14 ff 75 10 e8 8d ff ff ff 83 f8 00 75 0b 4f 3b 7d 08 73 e7}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Astaroth_2147839343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.psyH!MTB"
        threat_id = "2147839343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        info = "psyH: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {28 08 83 c0 01 39 d0 75 f7 89 f0 89 1c 24 c7 44 24 14 00 a0 05 00 88 44 24 10 8b 84 24 30 a0 05 00 89 44 24 18}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Astaroth_2147839344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.psyN!MTB"
        threat_id = "2147839344"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        info = "psyN: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {83 c4 18 8b 85 7c fe ff ff 39 45 dc 0f 8f a9 03 00 00 68 80 3a 40 00 68 70 3a 40 00 e8 41 0f 00 00 8b d0 8d 8d 68 ff ff ff}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Astaroth_2147839345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.psyQ!MTB"
        threat_id = "2147839345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        info = "psyQ: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {ff 15 54 f1 40 00 eb 43 02 03 02 03 03 03 02 03 03 02 03 02 03 03 03 02 03 c7 45 f4 97 00 00 00 ff 75 d8 eb d1}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Astaroth_2147839678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.psyO!MTB"
        threat_id = "2147839678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        info = "psyO: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {56 8b 06 05 98 16 40 00 ff d0 5e 83 c6 04 eb f0 8b ff 33 0a 45 4d}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Astaroth_2147839679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.psyR!MTB"
        threat_id = "2147839679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        info = "psyR: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {e8 9d ff ff ff a1 b0 70 40 00 50 e8 6e ff ff ff 85 c0 74 01 c3 a1 5c 86 40 00 c3 50 e8 5d ff ff ff 85 c0 74 db}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Astaroth_2147839687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.psyU!MTB"
        threat_id = "2147839687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        info = "psyU: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {ff 15 30 40 40 00 3b c7 75 05 39 7d fc 75 0a 83 f8 02 74 05 83 f8 05 75 60 6a 04 58 6a 18 89 45 f0 89 45 f4 58 89 7d f8}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Astaroth_2147839928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.psyX!MTB"
        threat_id = "2147839928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        info = "psyX: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {68 65 28 40 00 68 3d 28 40 00 6a 00 e8 09 20 00 00 c3 6a 00 68 70 28 40 00 68 85 03 00 00 68 00 20 40 00 ff 35 74 28 40 00 e8 da 1f 00 00}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Astaroth_2147839929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.psyY!MTB"
        threat_id = "2147839929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        info = "psyY: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {55 8b ec 81 ec 5c 02 00 00 56 57 6a 11 33 c0 59 8d 7d ac f3 ab 8d 7d f0 c7 45 ac 44 00 00 00 ab}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Astaroth_2147840197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.psyW!MTB"
        threat_id = "2147840197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        info = "psyW: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {76 13 8b 55 f4 2b d0 89 4d fc 8a 0c 02 88 08 40 ff 4d fc 75 f5 56}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Astaroth_2147840581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.psyG!MTB"
        threat_id = "2147840581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        info = "psyG: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {ff 15 18 20 40 00 a3 2c 33 40 00 8d 4d fc 50 51 ff 15 78 20 40 00 ff 15 00 20 40 00 8b 45 04 a3 9b 31 40 00 33 c0 b9 16 00 00 00 50 49 75 fc 68 00 7f 00 00 56}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Astaroth_2147840797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.psyE!MTB"
        threat_id = "2147840797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        info = "psyE: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {c1 e0 0c 50 59 50 ad 2b c8 03 f1 8b c8 57 51 49 8a 44 39 06 88 04 31 75 f6}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Astaroth_2147840798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.psyT!MTB"
        threat_id = "2147840798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        info = "psyT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {68 af fe a2 35 d8 0c ec 3e 03 b2 35 6a 4e fd d0 e1 bb 67 bc 89 5b 84 73 e1 e3 30 14 e0 dd bc 5d 69 31 63 9f 46 5a 8e 81 a8 9e 6c 2d f1 32 64 54 23 71 ce}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Astaroth_2147844898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.psyJ!MTB"
        threat_id = "2147844898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        info = "psyJ: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {67 00 6c 00 69 00 73 00 00 00 b0 04 02 00 ff ff ff ff 05 00 00 00 75 00 73 00 74 00 72 00 61}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Astaroth_2147844899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.psyP!MTB"
        threat_id = "2147844899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        info = "psyP: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {02 ff e0 68 d0 84 40 00 b8 30 15 40 00 ff d0 ff e0 00 00 00 07 00 00 00 75 73 65 72 33 32 00}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Astaroth_ZZ_2147920516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Astaroth.ZZ"
        threat_id = "2147920516"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "820"
        strings_accuracy = "Low"
    strings:
        $x_500_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 500, accuracy: High
        $x_100_2 = {0f b7 00 83 e8 41 8d 04 80 8d 04 80 8b 55 ?? 0f b7 52 02 83 ea 41 03 c2}  //weight: 100, accuracy: Low
        $x_100_3 = {8a 54 0a ff 80 ea 0a f6 d2 b9 00 00 00 00 e8}  //weight: 100, accuracy: High
        $x_100_4 = {0f b7 44 50 fe 33 45}  //weight: 100, accuracy: High
        $x_10_5 = "xGERAL.AR" ascii //weight: 10
        $x_10_6 = "BuildAvBanks" ascii //weight: 10
        $x_10_7 = "DeleteVerificaOFFx" ascii //weight: 10
        $x_10_8 = "verificaBloqsPrev" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_500_*) and 3 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}


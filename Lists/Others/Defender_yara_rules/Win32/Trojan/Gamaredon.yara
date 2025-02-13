rule Trojan_Win32_Gamaredon_RS_2147835735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gamaredon.RS!MTB"
        threat_id = "2147835735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamaredon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%USERPROFILE%\\PowerModule.exe" ascii //weight: 1
        $x_1_2 = "mshta vbscript:Execute" ascii //weight: 1
        $x_1_3 = {43 72 65 61 74 65 53 68 6f 72 74 63 75 74 28 [0-16] 5c 53 79 73 74 65 6d 20 56 6f 6c 75 6d 65 20 49 6e 66 6f 72 6d 61 74 69 6f 6e 2e 6c 6e 6b}  //weight: 1, accuracy: Low
        $x_1_4 = "spread-ss.ru" ascii //weight: 1
        $x_1_5 = {64 65 6c 20 2f 66 20 2f 71 20 [0-16] 5c 6e 74 75 73 65 72 2e 69 6e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gamaredon_2147839931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gamaredon.psyH!MTB"
        threat_id = "2147839931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamaredon"
        severity = "Critical"
        info = "psyH: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {8a 07 47 08 c0 74 dc 89 f9 79 07 0f b7 07 47 50 47 b9 57 48 f2 ae 55 ff 96 e8 cb 01 00 09 c0 74 07 89 03 83 c3 04 eb d8}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gamaredon_2147839932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gamaredon.psyI!MTB"
        threat_id = "2147839932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamaredon"
        severity = "Critical"
        info = "psyI: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {7e 28 bf 01 00 00 00 8b 45 fc 0f b6 44 38 ff 8d 4d f8 ba 02 00 00 00 e8 7c b5 fb ff 8b 55 f8 8b c6 e8 c2 78 fb ff 47 4b 75 dd 33 c0 5a 59 59 64 89 10 68 90 ce 44 00 8d 45 f8 ba 02 00 00 00 e8 00 76 fb ff c3 e9 b2 6f fb ff}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gamaredon_2147839933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gamaredon.psyJ!MTB"
        threat_id = "2147839933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamaredon"
        severity = "Critical"
        info = "psyJ: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {8b 48 08 83 c1 01 8b 95 88 fb ff ff 89 4a 08 ff 15 14 20 40 00 89 85 80 fb ff ff 8b 85 80 fb ff ff 50 68 dc 20 40 00 8d 4d ac 51 ff 15 44 20 40}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gamaredon_2147840199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gamaredon.psyK!MTB"
        threat_id = "2147840199"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamaredon"
        severity = "Critical"
        info = "psyK: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {ff 15 94 66 00 10 a3 8c 66 00 10 8d 4d d0 ba 60 48 00 10 b8 d4 48 00 10 e8 ac d6 ff ff 8b 45 d0 e8 60 d2 ff ff 50 a1 80 66 00 10 50}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gamaredon_2147840200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gamaredon.psyl!MTB"
        threat_id = "2147840200"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamaredon"
        severity = "Critical"
        info = "psyl: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {56 57 53 50 5b 8b d3 51 e8 e3 fc ff ff 59 e2 f7 5b 5f 5e 33 c0}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gamaredon_2147840201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gamaredon.psyO!MTB"
        threat_id = "2147840201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamaredon"
        severity = "Critical"
        info = "psyO: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {85 f7 74 2d 8a d3 8d 4c 24 10 80 c2 41 52 e8 d8 00 00 00 68 2c 41 40 00 8d 4c 24 14 e8 88 00 00 00 8d 4c 24 0c 8b 44 24 10 50 6a 00 e8 86 fc ff ff 03 f6 43 83 fb 1a 7c c7}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gamaredon_2147840202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gamaredon.psyP!MTB"
        threat_id = "2147840202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamaredon"
        severity = "Critical"
        info = "psyP: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {8a 01 41 84 c0 75 f9 2b ca 8b 55 fc 8b f1 2b d6 4a 83 cb ff 33 ff 89 5d fc 85 d2 7e 27 33 c9 85 f6}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gamaredon_2147840203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gamaredon.psyS!MTB"
        threat_id = "2147840203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamaredon"
        severity = "Critical"
        info = "psyS: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {8e 9b 4f 92 72 da 23 30 2b 3d ac ce 84 ad f4 98 6d bb 4f 94 81 cb 72 09 67 7b e6}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gamaredon_2147840582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gamaredon.psyM!MTB"
        threat_id = "2147840582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamaredon"
        severity = "Critical"
        info = "psyM: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {be 00 10 40 00 89 f7 bb 09 00 00 00 64 8b 15 30 00 00 00 52 6a 00 b9 4c 03 00 00 8a 06 28 d8 aa 46 e2 f8}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gamaredon_2147840583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gamaredon.psyU!MTB"
        threat_id = "2147840583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamaredon"
        severity = "Critical"
        info = "psyU: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {31 d2 8d 45 f4 64 8b 0a 64 89 02 89 08 c7 40 04 a8 47 40 00 89 68 08 a3 3c b6 4e 00}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gamaredon_2147840584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gamaredon.psyW!MTB"
        threat_id = "2147840584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamaredon"
        severity = "Critical"
        info = "psyW: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {31 13 90 90 90 90 90 90 90 83 c3 04 90 39 cb 90 90 90 90 7c eb}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gamaredon_2147840585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gamaredon.psyY!MTB"
        threat_id = "2147840585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamaredon"
        severity = "Critical"
        info = "psyY: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {ba 03 c9 48 82 23 f1 ab a0 f1 23 71 8a d4 2f 51 a2 27 fd b3 77 ee 8c 43 b3 99 9f 61 f7 14 51 5c 71 e2}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gamaredon_2147840799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gamaredon.psyR!MTB"
        threat_id = "2147840799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamaredon"
        severity = "Critical"
        info = "psyR: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {15 fc 71 f9 c5 5f 15 08 ce 74 7f 34 95 92 b3 81 1f 8c a7 52 8c 0c af 2f d2 3b db 3f 85 4b 78 26 7a df}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gamaredon_2147844891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gamaredon.psyE!MTB"
        threat_id = "2147844891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamaredon"
        severity = "Critical"
        info = "psyE: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {f3 a5 33 c9 33 c0 66 a5 [0-7] 8b d1 74 09 40 41 3d 00 e1 f5 05 7c ef 8d 45 f4 50 6a 40 52 53}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gamaredon_2147844900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gamaredon.psyQ!MTB"
        threat_id = "2147844900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamaredon"
        severity = "Critical"
        info = "psyQ: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {50 30 20 00 58 d8 90 00 54 84 54 00 c4 90 58 00 00 c4 2c 00 24 d4 5c 00 9c 8c 84 00 60 5c 58 00 4c b0 54 00 e0 e0 d8}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


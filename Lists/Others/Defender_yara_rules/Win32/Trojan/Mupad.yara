rule Trojan_Win32_Mupad_A_2147705980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mupad.A"
        threat_id = "2147705980"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mupad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "g.delyemo.ru/?prod=" wide //weight: 10
        $x_10_2 = "g.tvilikho.ru/?prod=" wide //weight: 10
        $x_10_3 = "g.azmagis.ru/%f3" wide //weight: 10
        $x_10_4 = "\\CurrentVersion\\RunOnce" wide //weight: 10
        $x_1_5 = {3a 00 61 00 72 00 67 00 73 00 00 00 2e 00 61 00 72 00 67 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 00 64 00 65 00 76 00 69 00 63 00 65 00 5c 00 6d 00 75 00 70 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Mupad_B_2147721187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mupad.B"
        threat_id = "2147721187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mupad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://leatherrope.top/index.htm" ascii //weight: 2
        $x_2_2 = "//threatenhighway.ru/index.htm" ascii //weight: 2
        $x_2_3 = "://tourjerkpig.ru/index.htm" ascii //weight: 2
        $x_1_4 = "/index.htm;crypt=2570;g.purecontinue.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Mupad_D_2147721194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mupad.D"
        threat_id = "2147721194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mupad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 89 45 f6 c7 45 e4 00 00 00 00 c7 45 cc 00 00 00 00 8b 4d b4 89 4d b8 ba ?? ?? ?? 00 85 d2 0f 84 ?? ?? 00 00 83 7d b8 00 0f 84 ?? ?? 00 00 b8 ?? ?? ?? 00 85 c0 0f 84 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 15 ?? ?? 40 00 6a 00 ff 15 ?? ?? 40 00 83 f8 23 74 ?? 8b ?? c8}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 ff 15 ?? ?? 40 00 85 c0 75 10 c7 45 c8 ff ff ff ff b9 40 00 00 00 51 ff 75 c4 ba 00 13 00 00 52 6a 00 b8 00 00 00 00 40 83 7d b8 42}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Mupad_D_2147721194_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mupad.D"
        threat_id = "2147721194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mupad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "://fellowrat125.gdn/index.htm" ascii //weight: 2
        $x_2_2 = "//perfectlybeneath.gdn/index.htm" ascii //weight: 2
        $x_2_3 = "//remainframe.gdn/index.htm" ascii //weight: 2
        $x_2_4 = "crypt=9327;g.licenceviolet.gdn" ascii //weight: 2
        $x_2_5 = {70 72 6f 74 6f 63 6f 6c 3d 76 35 [0-8] 26 65 68 3d [0-8] 26 76 3d [0-8] 6d 69 64 3d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Mupad_D_2147721194_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mupad.D"
        threat_id = "2147721194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mupad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 e4 00 00 00 00 c7 45 cc 00 00 00 00 8b 4d b4 89 4d b8 ba ?? ?? ?? 00 85 d2 0f 84 ?? ?? 00 00 83 7d b8 00 0f 84 ?? ?? 00 00 b8 ?? ?? ?? 00 85 c0 0f 84 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {89 45 c0 6a 00 ff 15 ?? ?? 40 00 6a 00 ff 15 ?? ?? 40 00 83 f8 23 74 08 6a 00 ff 15 ?? ?? 40 00 8b 55 c8 89 15 ?? ?? 4c 00 6a 00}  //weight: 1, accuracy: Low
        $x_1_3 = {85 c0 75 10 c7 45 c8 ff ff ff ff b9 40 00 00 00 51 ff 75 c4 b9 70 13 00 00 51 b9 00 00 00 00 51 83 7d b8 42}  //weight: 1, accuracy: High
        $x_1_4 = {6a 0a ff 15 ?? ?? 40 00 6a 00 ff 15 ?? ?? 40 00 85 c0 75 ?? a1 ?? ?? 40 00 89 45 b8 8b 4d b8 ff d1 a3 ?? ?? 4c 00 c7 45 b4 0c 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Mupad_E_2147721668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mupad.E"
        threat_id = "2147721668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mupad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "://nightstorm.gdn/index.htm" ascii //weight: 2
        $x_2_2 = "http://mayfamilystrength.gdn/index.htm" ascii //weight: 2
        $x_2_3 = "//remainframe.gdn/index.htm" ascii //weight: 2
        $x_2_4 = {63 72 79 70 74 3d [0-6] 3b 67 2e 6c 69 63 65 6e 63 65 76 69 6f 6c 65 74 2e 67 64 6e}  //weight: 2, accuracy: Low
        $x_2_5 = {70 72 6f 74 6f 63 6f 6c 3d 76 35 [0-8] 26 65 68 3d [0-8] 26 76 3d [0-8] 6d 69 64 3d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Mupad_E_2147721668_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mupad.E"
        threat_id = "2147721668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mupad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 e8 ?? 04 00 00 dd d8 83 c4 08 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 15 ?? ?? 40 00 83 f8 23 74 08 6a 00 ff 15 ?? ?? 40 00 8b [0-1] c8 [0-8] 00 6a 00 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 45 c8 ff ff ff ff b9 40 00 00 00 51 ff 75 c4 b9 70 13 00 00 51 b9 00 00 00 00 51 83 7d b8 42 74 ?? ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 0a ff 15 ?? ?? 40 00 6a 00 ff 15 ?? ?? 40 00 85 c0 75 1c 8b [0-4] 40 00 89 ?? b8 8b ?? b8 ff d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Mupad_F_2147721679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mupad.F"
        threat_id = "2147721679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mupad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 89 45 e0 6a 00 68 ?? ?? 41 00 6a 00 6a 00 68 ?? ?? 41 00 ff 15 ?? ?? 41 00 3d 57 00 07 80 0f 85 ?? 00 00 00 83 7d e0 00 75 16 b9 40 ?? 41 00 85 c9 75 0d ba ?? ?? 42 00 85 d2 0f 84 ?? 00 00 00 ff 15 ?? ?? 41 00}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 40 00 00 00 51 ff 75 e8 b8 20 17 00 00 50 6a 00 81 7d e0 0a 01 00 00 74 5d 6a 0a ff 15 ?? ?? 41 00 6a 00 6a 00 ff 15 ?? ?? 41 00 6a 00 6a 00 ff 15 ?? ?? 41 00 85 c0 75 14 89 5d f0 ba ff ff ff ff 52 59 ff 55 f0 a3 ?? ?? 4b 00 eb 0e}  //weight: 1, accuracy: Low
        $x_1_3 = {52 59 ff 55 f0 a3 ?? ?? 4b 00 eb 0e 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? 41 00 6a 00 ff 15 ?? ?? 41 00 c7 45 08 0a 00 00 00 6a 00 6a 00 6a 00 ff 15 ?? ?? 41 00 6a 00 6a 00 ff 15 ?? ?? 41 00 6a 0a 6a 00 6a 00 6a 00 ff 15 ?? ?? 41 00 b8 17 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mupad_G_2147722588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mupad.G"
        threat_id = "2147722588"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mupad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? 00 6a 00 ff 15 ?? ?? ?? 00 83 f8 23 74 08 6a 00 ff 15 ?? ?? ?? 00 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 04 68 00 10 00 00 68 40 1f 00 00 6a 00 ff 15 ?? ?? ?? 00 89 45 fc 8b 4d fc 89 4d b8 33 d2 8b 4d f4 e8}  //weight: 1, accuracy: Low
        $x_4_3 = {85 c0 75 09 b9 40 00 00 00 51 ff 75 c8 b9 70 13 00 00 51 b9 00 00 00 00 51 83 7d bc 42 74 ?? 6a 04 68 00 10 00 00 68 00 10 00 00 6a 00 ff 15}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


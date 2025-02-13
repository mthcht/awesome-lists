rule Trojan_Win32_Pikabot_DA_2147847371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.DA!MTB"
        threat_id = "2147847371"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 fc 88 08 eb ?? eb ?? 99 f7 7d ?? eb ?? 51 bb ?? ?? ?? ?? eb ?? 33 c8 8b 45 ?? eb ?? 0f b6 08 8b 45 ?? eb ?? 55 8b ec eb ?? 8b 45 ?? 0f b6 04 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_PA_2147847513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.PA!MTB"
        threat_id = "2147847513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 c7 45 [0-2] 00 00 00 8b c6 8d 0c 1e f7 75 ?? 8a 44 15 ?? 32 04 39 46 88 01 81 fe ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_PA_2147847513_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.PA!MTB"
        threat_id = "2147847513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 44 0d b4 34 [0-2] 88 44 0d e4 41 83 f9 19 7c f0}  //weight: 10, accuracy: Low
        $x_1_2 = {4a 70 55 71 [0-8] c7 45 ?? 61 76 7d 4d c7 45 ?? 6a 62 6b 76 c7 45 ?? 69 65 70 6d c7 45 ?? 6b 6a 54 76 c7 45 ?? 6b 67 61 77 [0-8] [0-8] 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_EM_2147847657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.EM!MTB"
        threat_id = "2147847657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8a 84 0d 70 ff ff ff 34 e2 0f b6 c0 66 89 84 4d 44 fc ff ff 41 83 f9 26 7c e6}  //weight: 6, accuracy: High
        $x_6_2 = {0f af 47 40 89 47 40 8b 8e 88 00 00 00 8b 46 48 33 c1 2b 4e 10 2b 4e 24 48 01 46 34}  //weight: 6, accuracy: High
        $x_6_3 = {0f b6 84 0d 70 ff ff ff 66 83 e8 40 66 23 c3 66 89 84 4d 2c fc ff ff 41 83 f9 26 7c e3}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Pikabot_DB_2147893292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.DB!MTB"
        threat_id = "2147893292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 5d cc 03 5d ac 81 eb ?? ?? ?? ?? 03 5d e8}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 d8 31 18}  //weight: 10, accuracy: High
        $x_1_3 = {ba 04 00 00 00 2b d0 01 55 d8 8b 45 e8 3b 45 d4}  //weight: 1, accuracy: High
        $x_1_4 = {bb 04 00 00 00 2b d8 [0-15] 2b d8 01 5d d8 8b 45 e8 3b 45 d4}  //weight: 1, accuracy: Low
        $x_1_5 = {83 45 e8 04 83 45 d8 04 8b 45 e8 3b 45 d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Pikabot_RPX_2147893916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.RPX!MTB"
        threat_id = "2147893916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 46 08 eb 3c 8b 4e 50 8b 46 38 83 c1 3f 8b 15 ?? ?? ?? ?? 03 c1 50 81 c2 00 30 00 00 52 ff 35 ?? ?? ?? ?? 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_RPY_2147893917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.RPY!MTB"
        threat_id = "2147893917"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 ff 7f 00 00 f7 f7 31 d2 8d 78 01 89 c8 8b 0c 9e f7 f7 01 d8 8d 04 86 8b 10 89 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_RPY_2147893917_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.RPY!MTB"
        threat_id = "2147893917"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 ed 01 86 9c 00 00 00 0f b6 c2 0f b6 56 68 0f af d0 a1 ?? ?? ?? ?? 88 14 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_RPY_2147893917_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.RPY!MTB"
        threat_id = "2147893917"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bb 00 00 00 00 21 5d f0 e9 52 02 00 00 e9 e0 02 00 00 bb 03 00 00 00 83 c3 05 eb 07 8b 45 f0 33 d2 eb ef 53 5e eb 14 8b 45 e8 03 45 f0 e9 84 02 00 00 bb 0c 00 00 00 03 e3 eb c5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_RPZ_2147893919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.RPZ!MTB"
        threat_id = "2147893919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 40 0c 53 56 57 8b 70 0c c7 45 a0 6b 00 65 00 c7 45 a4 72 00 6e 00 c7 45 a8 65 00 6c 00 c7 45 ac 33 00 32 00 c7 45 b0 2e 00 64 00 c7 45 b4 6c 00 6c 00 89 4d b8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_IP_2147894046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.IP!MTB"
        threat_id = "2147894046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 0c 8b 00 8b 00 8b 40 18 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_YAQ_2147894062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.YAQ!MTB"
        threat_id = "2147894062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Crash" ascii //weight: 1
        $x_1_2 = "beNotified" ascii //weight: 1
        $x_1_3 = "getFuncsArray" ascii //weight: 1
        $x_1_4 = "isUnicode" ascii //weight: 1
        $x_1_5 = "messageProc" ascii //weight: 1
        $x_1_6 = "setInfo" ascii //weight: 1
        $x_1_7 = "getName" ascii //weight: 1
        $x_1_8 = {50 ff d7 85 c0 75 20 46 81 fe 61 e6 01 00 7c d4 50 6a 01 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_DC_2147894067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.DC!MTB"
        threat_id = "2147894067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 08 8b 45 e8}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 f8 0f b6 44 10 10}  //weight: 1, accuracy: High
        $x_1_3 = {33 c8 8b 45 dc}  //weight: 1, accuracy: High
        $x_1_4 = {03 45 e8 88 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_AD_2147894419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.AD!MTB"
        threat_id = "2147894419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {8a 84 3d f8 fe ff ff 88 8c 3d f8 fe ff ff 88 84 35 f8 fe ff ff 0f b6 8c 3d f8 fe ff ff 0f b6 c0 03 c8 0f b6 c1 8a 84 05 f8 fe ff ff 32 04 13 88 02 42 83 6d fc 01 75}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_DD_2147894603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.DD!MTB"
        threat_id = "2147894603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 ec 0f b6 4c 05 90}  //weight: 1, accuracy: High
        $x_1_2 = {f7 f6 0f b6 44 15 8c}  //weight: 1, accuracy: High
        $x_1_3 = {33 c8 8b 45 ec}  //weight: 1, accuracy: High
        $x_1_4 = {88 4c 05 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_YZ_2147894803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.YZ!MTB"
        threat_id = "2147894803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e8 8b 55 d8 01 02 6a 00 e8 ?? ?? ?? ?? 8b 55 cc 03 55 ac 81 ea ?? ?? 00 00 03 55 e8 2b d0 8b 45 d8 31 10 83 45 e8 04 83 45 d8 04 8b 45 e8 3b 45 d4 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_ZU_2147895069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.ZU!MTB"
        threat_id = "2147895069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c3 89 45 f0 eb 3d}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 f0 33 d2 eb 00 b9 ?? ?? ?? ?? 83 c1 25 eb db 69 45 f0 ?? ?? ?? ?? bb 39 30 00 00 eb c6 b9 db 7f 00 00 83 c1 25 eb ca 8b 45 f0 33 d2 eb ef 48 89 45 ec e9 58 ff ff ff e9}  //weight: 1, accuracy: Low
        $x_1_3 = "Excpt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_ZY_2147895096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.ZY!MTB"
        threat_id = "2147895096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d ec 41 eb 79 b9 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? eb 45 03 c3 89 45 f0 eb 30 b9 3c 7f 00 00 81 c1 c4 00 00 00 eb 1c 69 45 f0 6d 4e c6 41 bb 39 30 00 00 eb de 48 89 45 ec e9}  //weight: 1, accuracy: Low
        $x_1_2 = "Crash" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_YY_2147895147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.YY!MTB"
        threat_id = "2147895147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 e4 0f b6 08 8b 45 e4 33 d2 bb ?? ?? ?? ?? 83 c3 ?? 53 5e f7 f6 8b 45 f8 [0-16] 0f b6 44 ?? ?? 33 c8 8b 45 dc 03 45 e4 88 08 8b 45 e4 40 89 45 e4 8b 45 e4 3b 45 b0 73 ?? 8b 45 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_RZ_2147895573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.RZ!MTB"
        threat_id = "2147895573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 dc 03 45 e4 e9}  //weight: 1, accuracy: High
        $x_1_2 = {f7 f6 8b 45 f8 eb}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 44 10 10 33 c8 eb}  //weight: 1, accuracy: High
        $x_1_4 = "Excpt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_YW_2147895705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.YW!MTB"
        threat_id = "2147895705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 e4 0f b6 08 8b 45 e4 33 d2 bb ?? ?? ?? ?? 83 c3 ?? 83 c3 ?? 53 5e f7 f6 8b 45 f8 0f b6 44 10 ?? 33 c8 8b 45 dc 03 45 e4 88 08 8b 45 e4 40 89 45 e4 8b 45 e4 3b 45 ?? 73 ?? 8b 45 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_YV_2147895805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.YV!MTB"
        threat_id = "2147895805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c3 89 45 f0 8b 45 f0 33 d2 b9 ?? ?? ?? ?? 83 c1 ?? f7 f1 8b 45 d8 89 94 85 ?? ?? ?? ?? 8b 45 d8 40 89 45 d8 8b 45 d8 3b 45 d4 7d ?? 69 45 f0 ?? ?? ?? ?? bb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_HO_2147895811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.HO!MTB"
        threat_id = "2147895811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 04 68 00 30 00 00 56 6a 00 ff 55}  //weight: 1, accuracy: High
        $x_1_2 = {8b c1 83 e0 07 8a 44 38 10 30 04 19 41 3b ce 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_YU_2147895892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.YU!MTB"
        threat_id = "2147895892"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c3 89 45 f0 8b 45 f0 33 d2 b9 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? f7 f1 8b 45 d8 89 94 85 ?? ?? ?? ?? 8b 45 d8 40 89 45 d8 8b 45 d8 3b 45 d4 7d ?? 69 45 f0 ?? ?? ?? ?? bb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_RB_2147897827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.RB!MTB"
        threat_id = "2147897827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {82 30 f5 3e 82 30 4b 3d ?? ?? ?? ?? 82 28 ef 3e 82 40 2d 3d 82 38 56 3e 82 40 2d 3e 82 58 14 3d 82 80 ?? ?? ?? ?? bd 3e 82 30 4b}  //weight: 1, accuracy: Low
        $x_1_2 = {66 c1 c0 0f f8 51 66 05 18 4b f5 a8 f0 66 85 ca 60 66 31 c3}  //weight: 1, accuracy: High
        $x_1_3 = {34 01 80 d3 2f f6 d0 fe cb d2 db fe c3 9c 2c bf d2 eb 53 f8 34 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Pikabot_FK_2147897832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.FK!MTB"
        threat_id = "2147897832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 02 6a 00 e8 fc fd fa ff 8b 55 cc 03 55 ac 81 ea 53 37 02 00 03 55 e8 2b d0 8b 45 d8 31 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_DE_2147897881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.DE!MTB"
        threat_id = "2147897881"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 cc 03 55 ac 81 ea 53 37 02 00 03 55 e8 2b d0 8b 45 d8 31 10 83 45 e8 04 83 45 d8 04 8b 45 e8 3b 45 d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_MMC_2147897914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.MMC!MTB"
        threat_id = "2147897914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b 40 0c}  //weight: 1, accuracy: High
        $x_1_2 = {8d 40 0c 8b 00 8b 40 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_DF_2147898362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.DF!MTB"
        threat_id = "2147898362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e8 8b 55 d8 01 02 8b 45 cc 03 45 ac 2d f2 5f 00 00 03 45 e8 8b 55 d8 31 02 83 45 e8 04 83 45 d8 04 8b 45 e8 3b 45 d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_MA_2147898557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.MA!MTB"
        threat_id = "2147898557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 41 40 8b cb 2b 05 ?? ?? ?? ?? 05 a5 0c 09 00 c1 e9 08 31 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 88 0c 10 8b 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 41 89 0d ?? ?? ?? ?? 88 1c 08 ff 05 ?? ?? ?? ?? 81 fe 34 6a 01 00 0f 8c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_CHY_2147898559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.CHY!MTB"
        threat_id = "2147898559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 0c 02 83 c2 04 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 83 c0 ee 8b 35 ?? ?? ?? ?? 33 c8 a1 ?? ?? ?? ?? 2b c1 89 0d ?? ?? ?? ?? 2d 98 fd 18 00 0f af 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8d 04 45 57 5e f9 ff 03 46 64 a3 ?? ?? ?? ?? 81 fa ?? ?? ?? 00 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_HT_2147898720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.HT!MTB"
        threat_id = "2147898720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d1 03 c2 0f b6 c0 89 45 ?? 8a 84 05 ?? ?? ?? ?? 88 84 3d ?? ?? ?? ?? 8b 45 ?? 88 8c 05 ?? ?? ?? ?? 0f b6 84 3d ?? ?? ?? ?? 03 c2 0f b6 c0 8a 84 05 ?? ?? ?? ?? 32 44 35 ?? 88 84 35 ?? ?? ?? ?? 46 83 fe ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_DG_2147898728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.DG!MTB"
        threat_id = "2147898728"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e8 0f b6 4c 05 80 8b 45 e8}  //weight: 1, accuracy: High
        $x_1_2 = {33 c8 8b 45 e8 88 4c 05 80}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_MB_2147898746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.MB!MTB"
        threat_id = "2147898746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 0c 08 8b 85 [0-4] 33 d2 be [0-4] f7 f6 0f b6 54 15 a8 33 ca}  //weight: 5, accuracy: Low
        $x_5_2 = {03 45 fc 2b 85 ?? ?? ?? ?? 2b 45 a0 8b 95 ?? ?? ?? ?? 88 0c 02 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_DH_2147898918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.DH!MTB"
        threat_id = "2147898918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 30 00 00 8b ?? f8 ?? 6a 00 ff 55}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 f6 0f b6 54 15 ?? 33 ca 8b 85 ?? ?? ff ff 11 00 0f b6 0c ?? 8b 85 ?? ?? ff ff 33 d2 be}  //weight: 1, accuracy: Low
        $x_1_3 = {5e 8b e5 5d c3 0e 00 88 0c ?? e9 ?? ?? ff ff ff 95 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_BMC_2147898987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.BMC!MTB"
        threat_id = "2147898987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 ca 8b 85 fc fe ff ff 03 85 44 ff ff ff 2b 85 14 ff ff ff 03 45 fc 03 45 bc 03 85 44 ff ff ff 2b 85 14 ff ff ff 03 45 fc 03 45 bc 03 85 44 ff ff ff 2b 85 14 ff ff ff 03 45 fc 03 45 bc 8b 95 0c ff ff ff 88 0c 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_AM_2147899157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.AM!MTB"
        threat_id = "2147899157"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 0a 8b 85 ?? ?? ?? ?? 33 d2 be ?? ?? ?? ?? f7 f6 0f b6 54 15 ?? 33 ca 8b 85 ?? ?? ?? ?? 0f af 85 ?? ?? ?? ?? 0f af 85 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 2b d0 8b 85 ?? ?? ?? ?? 0f af 85 ?? ?? ?? ?? 0f af 85 ?? ?? ?? ?? 2b d0 8b 85 ?? ?? ?? ?? 0f af 85 ?? ?? ?? ?? 0f af 85 ?? ?? ?? ?? 2b d0 8b 85 ?? ?? ?? ?? 88 0c 10 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_ZZ_2147900013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.ZZ!MTB"
        threat_id = "2147900013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "muesum.dna" ascii //weight: 1
        $x_1_2 = "eBurgerEvent_PasswordDetailDisplayed" wide //weight: 1
        $x_1_3 = "AVPamSyncExceptionClientDenied@passwdmgr@avast@com" ascii //weight: 1
        $x_1_4 = "avcfg://settings/Common/PasswordHash" ascii //weight: 1
        $x_1_5 = "avcfg://settings/Passwords/LeakCheckAl" ascii //weight: 1
        $x_1_6 = ".asw.pam.proto.BrowserCredential\\\\\"F" ascii //weight: 1
        $x_1_7 = "Received HTTP/0.9 when not allowed" wide //weight: 1
        $x_1_8 = "decyrillic" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Pikabot_ZX_2147900014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.ZX!MTB"
        threat_id = "2147900014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 47 01 0f b6 f8 8a 8c 3d ?? ?? ?? ?? 0f b6 d1 8d 04 13 0f b6 d8 8a 84 1d ?? ?? ?? ?? 88 84 3d ?? ?? ?? ?? 88 8c 1d ?? ?? ?? ?? 0f b6 84 3d ?? ?? ?? ?? 03 c2 0f b6 c0 8a 84 05 ?? ?? ?? ?? 32 44 35 d0 88 84 35 ?? ?? ?? ?? 46 83 fe ?? 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_DI_2147902659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.DI!MTB"
        threat_id = "2147902659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 0c 01 8b 85 ?? ?? ?? ?? 33 d2 be ?? ?? ?? ?? f7 f6 0f b6 54 15 ?? 33 ca}  //weight: 10, accuracy: Low
        $x_10_2 = {f7 f6 0f b6 54 15 ?? 33 ca 11 00 0f b6 8a ?? ?? ?? ?? 8b 45 ?? 33 d2 be}  //weight: 10, accuracy: Low
        $x_1_3 = {88 0c 02 eb}  //weight: 1, accuracy: High
        $x_1_4 = {88 08 eb c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Pikabot_PB_2147902746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.PB!MTB"
        threat_id = "2147902746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DllRegisterServer" ascii //weight: 1
        $x_1_2 = "DllUnregisterServer" ascii //weight: 1
        $x_2_3 = "GetUserProcessHost" ascii //weight: 2
        $x_4_4 = {f7 f6 0f b6 54 15 ?? 33 ca 8b 45 ?? 03 45 ?? 88 08 eb ?? 8b 4d ?? 51 e8}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Pikabot_DJ_2147902755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.DJ!MTB"
        threat_id = "2147902755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 35 ?? 32 44 19 ?? 88 43 ?? 8d 04 1f 3d 00 f6 02 00 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_MFK_2147902844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.MFK!MTB"
        threat_id = "2147902844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d e4 0f b6 89 ?? ?? ?? ?? 8b 45 e4 33 d2 be 1a 00 00 00 f7 f6 0f b6 54 15 b4 33 ca 8b 45 f0 03 45 e4 88 08 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "DllUnregisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_ROC_2147902859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.ROC!MTB"
        threat_id = "2147902859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 ff 8a 84 15 ?? ?? ?? ?? 89 d1 8a 94 1d f4 fe ff ff 88 94 0d f4 fe ff ff 8b 55 08 88 84 1d f4 fe ff ff 02 84 0d f4 fe ff ff 0f b6 c0 8a 84 05 ?? ?? ?? ?? 32 04 32 8b 55 18 88 04 32 46 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "DllUnregisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_SPDQ_2147902962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.SPDQ!MTB"
        threat_id = "2147902962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EkagfgMklgEXIHJPETq" ascii //weight: 1
        $x_1_2 = "GyCSoDEGSGUzJ" ascii //weight: 1
        $x_1_3 = "JhhZQnMfPCodgGg" ascii //weight: 1
        $x_1_4 = "LouYkKXd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_PC_2147903128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.PC!MTB"
        threat_id = "2147903128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {42 0f b6 d2 8a 84 15 [0-4] 01 c1 0f b6 c9 8a 9c 0d [0-4] 88 9c 15 [0-4] 88 84 0d [0-4] 02 84 15 [0-4] 0f b6 c0 8a 84 05 [0-4] 32 84 2e [0-4] 0f b6 c0 66 89 84 75 [0-4] 46 83 fe ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_PF_2147903391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.PF!MTB"
        threat_id = "2147903391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f6 0f b6 54 15 ?? 33 ca b8 01 00 00 00 6b d0 00 0f be 84 15 [0-4] 69 d0 [0-4] 8b 45 ?? 2b c2 8b 55 ?? 88 0c 02 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_PG_2147903428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.PG!MTB"
        threat_id = "2147903428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 d1 8a 94 1d [0-4] 88 94 0d [0-4] 8b 55 ?? 88 84 1d [0-4] 02 84 0d [0-4] 0f b6 c0 8a 84 05 [0-4] 32 04 32 8b 55 ?? 88 04 32 46 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_PH_2147904569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.PH!MTB"
        threat_id = "2147904569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f6 b8 01 00 00 00 6b c0 00 0f be 84 05 ?? ?? ?? ?? 6b c0 ?? be ?? 00 00 00 6b f6 ?? 0f be b4 35 ?? ?? ?? ?? 0f af c6 2b d0 0f b6 54 15 ?? 33 ca 8b 45 ?? 03 45 ?? 88 08 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_AS_2147905853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.AS!MTB"
        threat_id = "2147905853"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b c3 6a ?? 59 f7 f1 8a 44 15 ?? 30 04 3b 43 81 fb ?? ?? 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_PE_2147908378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.PE!MTB"
        threat_id = "2147908378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f6 0f b6 54 15 ?? 33 ca 8b 45 ?? 03 45 ?? 88 08 eb ?? 8b 4d ?? 51 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pikabot_FN_2147929143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikabot.FN!MTB"
        threat_id = "2147929143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikabot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 0f b6 d2 8a 84 15 e8 fb ff ff 01 c1 88 85 d4 fa ff ff 0f b6 c9 8a 84 0d e8 fb ff ff 88 84 15 e8 fb ff ff 8a 85 d4 fa ff ff 88 84 0d e8 fb ff ff 02 84 15 e8 fb ff ff 0f b6 c0 8a 84 05 e8 fb ff ff 32 84 2b 76 fb ff ff 0f b6 c0 66 89 84 5d 9c fb ff ff 43 83 fb 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


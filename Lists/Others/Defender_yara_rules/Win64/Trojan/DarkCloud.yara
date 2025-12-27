rule Trojan_Win64_DarkCloud_DB_2147942806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DarkCloud.DB!MTB"
        threat_id = "2147942806"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 01 43 0f b6 0c 01 01 c1 0f b6 c1 48 8b 4d b0 8a 04 01 48 63 4d f4 41 30 04 0a 8b 45 f4 83 c0 01 89 45 e0 8b 05 ?? ?? ?? ?? 8d 48 ff 0f af c8 f6 c1 01 b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DarkCloud_SX_2147947642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DarkCloud.SX!MTB"
        threat_id = "2147947642"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 fd 21 dd 31 fb 44 89 cf 09 eb 89 d5 44 21 fd 41 31 d7 41 09 ef 89 da f7 d2}  //weight: 5, accuracy: High
        $x_3_2 = {4c 89 84 24 80 00 00 00 4c 89 c6 48 21 fe 48 09 de 48 31 fe 48 89 f3 48 f7 d3 48 bf ?? ?? ?? ?? ?? ?? ?? ?? 48 21 fb 48 f7 d7}  //weight: 3, accuracy: Low
        $x_2_3 = {48 89 d9 31 d2 45 31 c0 45 31 c9 ff 15 ?? ?? ?? ?? 85 c0 b8 e5 ad 15 4e 41 0f 44 c6 3d 43 2e 7a 25}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


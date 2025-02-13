rule Trojan_Win32_Shifu_DSK_2147751964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shifu.DSK!MTB"
        threat_id = "2147751964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shifu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d2 33 3d ?? ?? ?? ?? 8b cf b8 04 00 00 00 03 c1 83 e8 04 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 16 81 c2 9c 43 cd 01 89 16 83 c6 04 83 e8 01 89 15 ?? ?? ?? ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Shifu_AW_2147820327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shifu.AW!MTB"
        threat_id = "2147820327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shifu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b ca 2b c8 83 e9 2b 8d 79 ea 81 ff 5e 02 00 00 76 07 8b c8 2b ca 83 e9 4b 83 f9 09 74 1e 83 f9 0c 74 0a 8d 3c 09 2b f8 83 ef 26 eb 1d 8d 04 cd 00 00 00 00 8b f8 8b c2 2b c7 eb 10 0f b6 d0 8d 54 0a 08 0f b7 fa 2b f8 03 f9 8b c7 83 ee 01 75 af}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shifu_GAB_2147898575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shifu.GAB!MTB"
        threat_id = "2147898575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shifu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b6 63 32 ca 00 01 00 c8 0a d3 8b 16}  //weight: 10, accuracy: High
        $x_10_2 = {32 00 02 04 00 cc cc 4f 66 23 19 4e 6c 47 58 00 a4 a4 ?? ?? ?? ?? 06 84 18}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shifu_A_2147908198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shifu.A!MTB"
        threat_id = "2147908198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shifu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 89 d3 66 2b ?? ?? 66 09 df 2b 45}  //weight: 2, accuracy: Low
        $x_2_2 = {01 d1 8b b4 24 ?? ?? ?? ?? 31 c6 89 b4 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


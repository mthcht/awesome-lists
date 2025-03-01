rule Trojan_Win32_ShadowPad_A_2147723094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShadowPad.A!dha"
        threat_id = "2147723094"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShadowPad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "300"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "D:\\tortoiseSVN\\nsc5\\bin\\Release\\nssock2.pdb" ascii //weight: 100
        $x_100_2 = "###ERROR###" ascii //weight: 100
        $x_100_3 = {6a 40 68 00 10 00 00 68 [0-2] 00 00 6a 00 ff 15}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShadowPad_E_2147723170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShadowPad.E!dha"
        threat_id = "2147723170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShadowPad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 14 0f 32 d0 88 11 8b d0 69 c0 ?? ?? ?? ?? c1 ea 10 69 d2}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 4c 24 04 55 89 e5 81 ec 00 04 00 00 51 68 ?? ?? 00 00 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShadowPad_A_2147921618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShadowPad.A!MTB"
        threat_id = "2147921618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShadowPad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 33 cf 7f a6 05 e2 a7 f7 b5 98 cc 48 42 1f cf 1e 2d 59 0a 62 b1 ed d6 64}  //weight: 1, accuracy: High
        $x_1_2 = {83 60 03 00 80 60 1f 80 83 60 33 00 66 c7 40 ff 00 0a 66 c7 40 20 0a 0a c6 40 2f 00 8b 0f 83 c0 40 03 ce}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShadowPad_B_2147921619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShadowPad.B!MTB"
        threat_id = "2147921619"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShadowPad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {19 51 00 00 0f 85 b0 0e 00 00 e8 60 29 00 00 3c 01}  //weight: 1, accuracy: High
        $x_1_2 = {48 55 8b ec 8b 45 08 e8 b2 29 00 00 57 67 00 00 14 5f e8 a7 29 00 00 92 69 00 00 43 e8 6a 4e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShadowPad_C_2147921620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShadowPad.C!MTB"
        threat_id = "2147921620"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShadowPad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 5d e8 c7 45 ec 56 69 72 74 c7 45 f0 75 61 6c 50 c7 45 f4 72 6f 74 65 66 c7 45 f8 63 74 c6 45 fa 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b f9 8b f2 8b 5d 08 33 c0 40 89 45 e4 85 f6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShadowPad_GA_2147932645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShadowPad.GA!MTB"
        threat_id = "2147932645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShadowPad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "{%8.8x-%4.4x-%4.4x-%8.8x%8.8x}" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_HeavensGate_RPY_2147893182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HeavensGate.RPY!MTB"
        threat_id = "2147893182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HeavensGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 0c 48 83 ec 28 0f 05 48 8b 4d b8 48 8d 64 cc 28 5f 48 89 45 b0 e8 00 00 00 00 c7 44 24 04 23 00 00 00 83 04 24 0d cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_HeavensGate_GVA_2147946472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HeavensGate.GVA!MTB"
        threat_id = "2147946472"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HeavensGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 75 14 8b 45 10 01 d0 0f b6 08 8b 55 08 8b 45 f4 01 d0 31 cb 89 da 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_HeavensGate_SX_2147962368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HeavensGate.SX!MTB"
        threat_id = "2147962368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HeavensGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {8b ec 83 ec 0c 8b 45 ?? b9 10 27 00 00 f7 e1 f7 d8 83 d2 00 f7 da 89 45}  //weight: 30, accuracy: Low
        $x_20_2 = {c6 45 bc 5c c6 45 bd 41 c6 45 be 70 c6 45 bf 70 c6 45 c0 44 c6 45 c1 61 c6 45 c2 74 c6 45 c3 61 c6 45 c4 5c c6 45 c5 4c c6 45 c6 6f c6 45 c7 63 c6 45 c8 61 c6 45 c9 6c c6 45 ca 5c c6 45 cb 53 c6 45 cc 74 c6 45 cd 65 c6 45 ce 61 c6 45 cf 6d c6 45 d0 5c}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


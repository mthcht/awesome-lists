rule Trojan_Win32_Potao_A_2147645580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Potao.A"
        threat_id = "2147645580"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Potao"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 6e 65 77 2f 74 61 73 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 6f 64 65 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = "FzsptxlzhX_" ascii //weight: 1
        $x_1_4 = {48 8d bd 02 ff ff ff 8d b5 00 ff ff ff 89 45 08 33 d2 2b fb 8b c3 2b f3 8a 08 66 c7 44 07 ff 00 00 80 f9 0d 75 05 88 0c 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Potao_B_2147648018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Potao.B"
        threat_id = "2147648018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Potao"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "id=%s&code=%d" ascii //weight: 1
        $x_1_2 = {81 7d 1c 07 20 01 00 8b f0 75 ?? a1}  //weight: 1, accuracy: Low
        $x_1_3 = {80 fa 0a 75 05 88 14 0e eb 0b 2a}  //weight: 1, accuracy: High
        $x_1_4 = {88 07 47 4b 75 f1 09 00 6a 7a 6a 61 e8}  //weight: 1, accuracy: Low
        $x_1_5 = {dd 1c 24 33 c0 ff d0 03 00 dd 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Potao_MKV_2147931752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Potao.MKV!MTB"
        threat_id = "2147931752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Potao"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b c8 0f b6 4c 11 ff 30 0c 02 8b 73 0c 0f b7 53 ?? 0f b6 0c 06 2b d0 30 4c 32 ff 0f b7 4b 10 8b 53 0c 2b c8 40 0f b6 4c 11 ?? 30 4c 02 ff 0f b7 4b 10 d1 e9 3b c1 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


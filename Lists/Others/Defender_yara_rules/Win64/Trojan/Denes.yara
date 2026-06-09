rule Trojan_Win64_Denes_NE_2147968219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Denes.NE!MTB"
        threat_id = "2147968219"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Denes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 8a 44 09 08 48 8d 51 01 42 88 84 11 ?? ?? ?? ?? 48 33 ca 0f 9d c0 48 85 c9 79 09 48 8b c2 48 33 c6 0f 9d c0 84 c0 0f 84 96 05 00 00 48 3b d7 7d 05 48 8b ca eb a6 4c 8b c6 48 8b d6 b9 2c 00 00 00 49 8b fd}  //weight: 2, accuracy: Low
        $x_2_2 = {0f 9c c0 7c 2b 48 8b 0b 49 2b c8 48 8b c1 48 33 03 0f 9d c2 48 85 c0 79 09 49 f7 d0 4c 33 c1 0f 9d c2 84 d2 74 d0 48 83 f9 04 40 0f 9c c7 eb 03 40 8a f8}  //weight: 2, accuracy: High
        $x_1_3 = "[dbg] connected, waiting for offset" ascii //weight: 1
        $x_1_4 = "POST" ascii //weight: 1
        $x_1_5 = "heartbeat (Async)" ascii //weight: 1
        $x_1_6 = "pumpRemoteToVps" ascii //weight: 1
        $x_1_7 = "payload too large" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Denes_ND_2147971203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Denes.ND!MTB"
        threat_id = "2147971203"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Denes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 c2 fb 49 8d 71 ff 41 8b c1 41 bc 01 00 00 00 d3 e8 0f b6 c8 b8 00 00 00 3f 42 8a 0c 11 02 ca 41 8b d4 80 e1 3f 48 d3 e2 48 81 c2 ff 0f 00 00 48 81 e2 00 f0 ff ff 48 03 f2 48 f7 da 48 23 f2 48 3b f0 48 0f 4f f0 41 3b f7}  //weight: 2, accuracy: High
        $x_1_2 = {3b f8 4d 1b c0 41 83 e0 08 49 8b c8 4c 8d 15 04 ef 04 00 d3 e8 0f b6 c0 4a 0f be 0c 10 48 8b c2 48 c1 e0 05 49 03 c8 48 03 c1 48 8b bc c3 68 10 00 00 48 85 ff}  //weight: 1, accuracy: High
        $x_2_3 = {0f b6 c0 48 0f be 14 10 48 03 d1 8d 4a fb 80 e1 3f 4c 8d 42 fa 48 d3 fb 49 8b c8 48 83 c3 e0 48 c1 e1 05 48 03 cb 48 89 5c 24 28 4c 89 44 24 20 48 8b 84 cf 68 10 00 00 48 89 46 18 48 8b 84 cf 68 10 00 00 48 85 c0 74 04}  //weight: 2, accuracy: High
        $x_1_4 = "[dbg] connected, waiting for offset" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


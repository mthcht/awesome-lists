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


rule Trojan_Win64_TinyNuke_LR_2147982268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TinyNuke.LR!MTB"
        threat_id = "2147982268"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TinyNuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {ff c1 0f b6 c9 44 0f b6 8c 0c f0 01 00 00 44 00 ca 44 0f b6 d2 46 0f b6 9c 14 f0 01 00 00 44 88 9c 0c f0 01 00 00 46 88 8c 14 f0 01 00 00 46 0f b6 54 00 01 44 02 8c 0c f0 01 00 00 45 0f b6 c9 46 32 94 0c f0 01 00 00 46 88 14 06 49 ff c0 4c 39 c3}  //weight: 20, accuracy: High
        $x_10_2 = {4c 33 84 24 e0 00 00 00 4c 0f af c7 4c 33 84 24 d8 00 00 00 4c 0f af c7 4c 33 84 24 c0 00 00 00 4c 0f af c7 4c 33 84 24 b8 00 00 00 4c 0f af c7 4c 33 84 24 b0 00 00 00 4c 0f af c7 4c 33 84 24 a8 00 00 00 4c 0f af c7 4c 33 84 24 a0 00 00 00 4c 0f af c7 4c 33 84 24 98 00 00 00 4c 0f af c7}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


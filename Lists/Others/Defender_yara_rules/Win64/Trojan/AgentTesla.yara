rule Trojan_Win64_AgentTesla_GVI_2147951451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AgentTesla.GVI!MTB"
        threat_id = "2147951451"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 54 16 10 41 03 d1 44 0f b6 e2 43 8d 14 a4 ff c2 44 0f b6 e2 8b d1 0f b6 44 13 10 44 8b c8 41 d1 f9 c1 e0 07 41 0b c1 0f b6 c0 41 33 c4 41 88 44 16 10 ff c1 3b e9 7f 9d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


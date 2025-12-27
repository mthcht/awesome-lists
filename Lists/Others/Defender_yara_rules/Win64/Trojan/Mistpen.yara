rule Trojan_Win64_Mistpen_SX_2147958428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mistpen.SX!MTB"
        threat_id = "2147958428"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mistpen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {44 8b 4d 9b 48 8d 45 cf 4c 8b 45 b7 48 8d 15 ?? ?? ?? ?? 48 89 44 24 28 48 8d 4d d7 48 8d 45 bf 48 89 44 24 20 e8 ?? ?? ?? ?? 48 8b 75 bf 0f b6 0e 83 e9 64}  //weight: 6, accuracy: Low
        $x_4_2 = {48 8d 4d cf 48 83 65 a7 00 83 65 97 00 89 45 cf 8a 05 ?? ?? ?? ?? 88 45 d3 e8 ?? ?? ?? ?? b9 40 00 00 00 48 8b d8 8d 50 40 ff 15 ?? ?? ?? ?? 48 8d 56 01 41 b8 08 00 00 00 48 8b c8 48 8b f8 e8}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


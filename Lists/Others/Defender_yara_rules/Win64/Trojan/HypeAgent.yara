rule Trojan_Win64_HypeAgent_AH_2147977116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/HypeAgent.AH!MTB"
        threat_id = "2147977116"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "HypeAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {88 45 d8 0f b6 41 01 34 f8 88 45 d9 0f b6 41 02 34 a1 88 45 da 0f b6 41 03 34 ce 88 45 db 0f b6 41 04 34 c5 88 45 dc 0f b6 41 05 34 66 88 45 dd 0f b6 41 06 34 05 88 45 de 0f b6 41 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


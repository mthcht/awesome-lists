rule Trojan_Win64_Starter_ASA_2147953213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Starter.ASA!MTB"
        threat_id = "2147953213"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Starter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 48 63 d0 48 8b 45 10 48 01 c2 8b 45 fc 48 98 48 8d 0c ?? ?? ?? ?? ?? 48 8b 45 18 48 01 c8 8b 00 48 98 83 e0 3f 0f b6 44 05 b0 88 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


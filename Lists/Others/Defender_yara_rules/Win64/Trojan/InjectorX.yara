rule Trojan_Win64_InjectorX_CS_2147853209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/InjectorX.CS!MTB"
        threat_id = "2147853209"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "InjectorX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff c2 0f b6 d2 0f b6 9c 15 a0 00 00 00 40 00 de 40 02 b4 15 b0 01 00 00 44 0f b6 d6 42 0f b6 84 15 a0 00 00 00 88 84 15 a0 00 00 00 42 88 9c 15 a0 00 00 00 02 9c 15 a0 00 00 00 0f b6 c3 0f b6 84 05 a0 00 00 00 41 30 04 38 48 ff c7 49 39 fe}  //weight: 1, accuracy: High
        $x_1_2 = "computerholocaust" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


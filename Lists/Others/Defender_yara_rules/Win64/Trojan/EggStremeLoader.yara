rule Trojan_Win64_EggStremeLoader_C_2147952130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EggStremeLoader.C!MTB"
        threat_id = "2147952130"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EggStremeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 63 ca 8a 04 31 41 88 04 30 44 88 0c 31 41 0f b6 0c 30 49 03 c9 0f b6 c1 8a 0c 30 41 30 0c 24 4d 03 e3 4d 2b d3 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_EggStremeLoader_CA_2147952134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EggStremeLoader.CA!MTB"
        threat_id = "2147952134"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EggStremeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c9 48 8d 05 ?? ?? ?? ?? 8a 04 01 34 dd 88 84 0d ?? ?? ?? ?? 48 ff c1 48 83 f9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


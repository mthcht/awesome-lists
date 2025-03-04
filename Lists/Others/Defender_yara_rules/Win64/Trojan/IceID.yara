rule Trojan_Win64_IceId_PBE_2147845890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IceId.PBE!MTB"
        threat_id = "2147845890"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IceId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f0 11 01 83 ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? ff c8 03 c8 48 8b 83 ?? ?? ?? ?? 31 4b 54 41 8b d0 48 63 8b ?? ?? ?? ?? c1 ea 10 88 14 01 41 8b d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_IceId_PBE_2147845890_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/IceId.PBE!MTB"
        threat_id = "2147845890"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "IceId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d0 8b c2 03 c8 8b c1 03 05 ?? ?? ?? ?? 48 98 48 8d 0d ?? ?? ?? ?? 0f be 04 01 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 48 63 4c 24 50 48 8b 54 24 68 88 04 0a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


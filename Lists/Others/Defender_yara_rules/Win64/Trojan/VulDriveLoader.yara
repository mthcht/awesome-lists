rule Trojan_Win64_VulDriveLoader_SA_2147890395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VulDriveLoader.SA!MTB"
        threat_id = "2147890395"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VulDriveLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 ff c0 48 89 45 ?? 48 8b 45 ?? 48 39 45 ?? 73 ?? 48 8b 85 ?? ?? ?? ?? 48 8b 4d ?? 0f b7 04 48 0f b7 8d ?? ?? ?? ?? 33 c1 48 8b 4d ?? 48 8b 55 ?? 66 89 04 51 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_Wacapew_GK_2147850839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Wacapew.GK!MTB"
        threat_id = "2147850839"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Wacapew"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f0 3d 48 63 4c 24 20 88 84 0c ?? ?? ?? ?? 48 63 44 24 20 0f b6 84 04 ?? ?? ?? ?? 05 8e 00 00 00 48 63 4c 24 20 88 84 0c ?? ?? ?? ?? 48 63 44 24 20 0f b6 84 04 ?? ?? ?? ?? 05 82 00 00 00 48 63 4c 24 20 88 84 0c ?? ?? ?? ?? 48 63 44 24 20 0f b6 84 04 ?? ?? ?? ?? 05 ae 00 00 00 48 63 4c 24 20 88 84 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


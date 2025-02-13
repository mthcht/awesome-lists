rule Trojan_Win64_Mopone_AA_2147900010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mopone.AA!MTB"
        threat_id = "2147900010"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mopone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 63 4c 24 ?? 88 84 0c ?? ?? ?? ?? 48 63 44 24 ?? 0f b6 84 04 ?? ?? ?? ?? 83 f0 ?? 48 63 4c 24 ?? 88 84 0c ?? ?? ?? ?? 48 63 44 24 ?? 0f b6 84 04 ?? ?? ?? ?? 2d ?? ?? ?? ?? 48 63 4c 24 ?? 88 84 0c ?? ?? ?? ?? 48 63 44 24 ?? 0f b6 84 04 ?? ?? ?? ?? 05 ?? ?? ?? ?? 48 63 4c 24 ?? 88 84 0c ?? ?? ?? ?? e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


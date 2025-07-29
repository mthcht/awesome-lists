rule Trojan_Win64_Phave_MR_2147947780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Phave.MR!MTB"
        threat_id = "2147947780"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Phave"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 89 c1 48 8b 05 ?? ?? 00 00 ff d0 48 89 85 ?? ?? 00 00 48 83 bd ?? ?? 00 00 00 75 0a b8 01 00 00 00 e9 ?? ?? 00 00 48 8b 85 ?? ?? 00 00 48 8d 15 ?? ?? 00 00 48 89 c1 48 8b 05 ?? ?? 00 00 ff d0}  //weight: 5, accuracy: Low
        $x_10_2 = {48 01 d0 0f b6 00 48 8b 8d ?? ?? 00 00 48 8b 95 ?? ?? 00 00 48 01 ca 32 85 ?? ?? 00 00 88 02 48 83 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_DonuLoader_EI_2147956682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DonuLoader.EI!MTB"
        threat_id = "2147956682"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DonuLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 f7 f1 48 8b c2 48 6b c0 ?? 48 8d 8c 24 ?? ?? ?? ?? 48 03 c8 48 8b c1 0f b6 00 8b 4c 24 ?? 33 c8 8b c1 88 44 24 ?? 48 8d 54 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


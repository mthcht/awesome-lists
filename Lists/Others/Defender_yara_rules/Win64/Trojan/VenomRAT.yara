rule Trojan_Win64_VenomRAT_AG_2147980333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VenomRAT.AG!MTB"
        threat_id = "2147980333"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VenomRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 0f b6 fa 05 39 30 00 00 46 32 94 3c 20 09 00 00 31 c8 43 8d 0c 30 45 88 53 ?? 41 31 cc 89 f9 44 8d 0c 02 41 89 c0 c1 c1 ?? 45 31 c8 44 01 e1 44 8d b4 0a ?? ?? ?? ?? 4d 39 eb 75}  //weight: 5, accuracy: Low
        $x_5_2 = "%sag_runtime_payload.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


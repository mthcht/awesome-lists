rule Trojan_Win64_UmbralStealer_PGUS_2147969093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/UmbralStealer.PGUS!MTB"
        threat_id = "2147969093"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "UmbralStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8d 8c 24 [0-31] 45 0f b6 ?? ?? 0f b6 ?? e8 [0-10] 8a 84 ?? ?? ?? ?? ?? 42 02 84 ?? ?? ?? ?? ?? 0f b6 c0 8a 84 04 [0-5] 30 44 ?? ff ?? ff ?? ?? 81 ?? ?? ?? ?? ?? 75}  //weight: 5, accuracy: Low
        $x_5_2 = {0f b6 d2 45 0f b6 c0 8a 04 11 42 32 04 01 88 04 11 42 32 04 01 42 88 04 01 30 04 11}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


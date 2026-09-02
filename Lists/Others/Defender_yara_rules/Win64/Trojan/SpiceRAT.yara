rule Trojan_Win64_SpiceRAT_AA_2147977352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SpiceRAT.AA!MTB"
        threat_id = "2147977352"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SpiceRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {48 8b 54 0d 10 48 31 14 0f 48 83 c1 ?? 48 39 c8 75}  //weight: 11, accuracy: Low
        $x_9_2 = {0f b6 4c 05 ?? 30 0c 07 0f b6 4c 05 11 30 4c 07 ?? 0f b6 4c 05 12 30 4c 07 ?? 0f b6 4c 05 13 30 4c 07}  //weight: 9, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


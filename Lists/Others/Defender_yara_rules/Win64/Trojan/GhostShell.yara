rule Trojan_Win64_GhostShell_PAHW_2147980219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GhostShell.PAHW!MTB"
        threat_id = "2147980219"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GhostShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 8d 47 0c 45 8b ?? 41 [0-3] 4c 03 ?? 41 32 ?? ?? 3c 4d 75 ?? 49 8b ?? 41 8d 48 01 48 c1 e8 08 32 04 ?? 3c 5a 74}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


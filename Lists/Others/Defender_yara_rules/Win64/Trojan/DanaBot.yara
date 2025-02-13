rule Trojan_Win64_DanaBot_SA_2147897831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DanaBot.SA!MTB"
        threat_id = "2147897831"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DanaBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 0f b6 00 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 0f af 45 ?? 0f af 45 ?? 8b 4d ?? 03 c8 33 4d ?? 89 4d ?? 83 45 ?? ?? 83 eb ?? 85 db 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_WinLolRAT_PA_2147980089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WinLolRAT.PA!MTB"
        threat_id = "2147980089"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WinLolRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 31 d1 0f b6 50 ?? 44 0f b6 40 ?? 44 0f b6 48 ?? 0f b6 40 ?? c1 e0 ?? 41 c1 e1 ?? 41 09 c1 41 c1 e0 ?? 45 09 c8 41 09 d0 41 81 f0 41 df dd 45 48 89 8c 24 ?? ?? ?? ?? 44 89 84 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_WinLolRAT_PC_2147980359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WinLolRAT.PC!MTB"
        threat_id = "2147980359"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WinLolRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GET /payload.bin HTTP/1.0" ascii //weight: 1
        $x_1_2 = "http://%s/payload.bin" ascii //weight: 1
        $x_4_3 = "103.193.173.83" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


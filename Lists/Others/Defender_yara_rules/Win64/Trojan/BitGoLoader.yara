rule Trojan_Win64_BitGoLoader_A_2147912274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BitGoLoader.A!MTB"
        threat_id = "2147912274"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BitGoLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " Go build ID:" ascii //weight: 1
        $x_1_2 = "main.RedirectToPayload" ascii //weight: 1
        $x_1_3 = "main.HollowProcess" ascii //weight: 1
        $x_1_4 = "main.AesDecode.func1" ascii //weight: 1
        $x_1_5 = "main._RunPE" ascii //weight: 1
        $x_1_6 = "h1:6oNBlSdi1QqM1PNW7FPA6xOGA5UNsXnkaYZz9vdPGhA=" ascii //weight: 1
        $x_1_7 = "h1:UQHMgLO+TxOElx5B5HZ4hJQsoJ/PvUvKRhJHDQXO8P8=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


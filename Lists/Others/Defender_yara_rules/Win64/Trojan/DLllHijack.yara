rule Trojan_Win64_DLllHijack_AHA_2147966580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLllHijack.AHA!MTB"
        threat_id = "2147966580"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLllHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {0f b6 10 41 01 d1 45 0f b6 d9 4d 89 d9 ?? ?? ?? 45 0f b6 23 44 88 20 41 88 13 02 10 0f b6 d2 0f b6 44 14 20 41 ?? 02 49 83 c2 01 49 39 fa 75}  //weight: 20, accuracy: Low
        $x_20_2 = {48 89 c8 48 89 cf 49 f7 e1 48 d1 ea 48 8d 04 92 48 8d 04 42 48 29 c7 41 0f b6 04 38 30 04 0b 48 83 c1 ?? 48 39 ce 75}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


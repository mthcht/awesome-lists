rule Trojan_Win64_PoolRAT_MKX_2147960707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolRAT.MKX!MTB"
        threat_id = "2147960707"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 8b f9 0f 1f 84 00 ?? ?? ?? ?? 48 8d 4c 24 20 e8 ?? ?? ?? ?? 30 03 48 8d 5b 01 48 83 ef 01 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


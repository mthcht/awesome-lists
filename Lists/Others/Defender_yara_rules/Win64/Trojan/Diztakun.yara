rule Trojan_Win64_Diztakun_MKV_2147906806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Diztakun.MKV!MTB"
        threat_id = "2147906806"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Diztakun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 33 c0 8b c8 c1 e9 11 33 c8 b8 ?? ?? ?? ?? 44 8b c1 41 c1 e0 05 44 33 c1 41 f7 e0 41 0f b7 c3 c1 ea 05 0f b7 ca 0f af c8 41 0f b7 c0 66 2b c1 66 83 c0 61 66 42 89 04 53 49 ff c2 4d 3b d1 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


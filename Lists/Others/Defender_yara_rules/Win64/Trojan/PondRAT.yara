rule Trojan_Win64_PondRAT_MKV_2147960604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PondRAT.MKV!MTB"
        threat_id = "2147960604"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PondRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {48 8b c3 48 8d 52 01 83 e0 1f 48 ff c3 0f b6 44 05 ?? 30 42 ff 49 83 e8 01 75}  //weight: 4, accuracy: Low
        $x_5_2 = {8b d6 44 8b c3 48 8b c2 48 8d 49 01 83 e0 1f 48 ff c2 0f b6 44 05 ?? 30 41 ff 49 83 e8 01 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


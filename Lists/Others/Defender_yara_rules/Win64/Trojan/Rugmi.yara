rule Trojan_Win64_Rugmi_MKV_2147923016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rugmi.MKV!MTB"
        threat_id = "2147923016"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d3 eb 41 33 da 41 2b da 89 d9 41 0f af c9 81 c1 80 00 00 00 c1 e9 08 81 f1 00 00 80 00 81 e9 00 00 80 00 8b d9 48 0f b6 4c ?? ?? d3 e3 2b 1a 89 1a 48 83 c2 04 48 83 c0 04 41 83 c0 01 45 3b c3 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


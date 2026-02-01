rule Trojan_Win64_Striker_AHB_2147962121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Striker.AHB!MTB"
        threat_id = "2147962121"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Striker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {48 ba 43 5d 2f 61 67 65 6e 74 49 89 c4 48 89 54 24 6c 48 b8 5b 4f 42 46 53 5f 45 4e}  //weight: 30, accuracy: High
        $x_20_2 = {44 8d 42 01 41 0f af c0 89 c3 84 db 75 ?? 83 c3 ?? eb ?? 80 fb ?? 74 ?? 8d 43 e0 3c ?? 76 ?? 30 1c 16 48 ff c2 eb}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


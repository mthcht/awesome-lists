rule Trojan_Win64_FallenMiner_BSA_2147932245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FallenMiner.BSA!MTB"
        threat_id = "2147932245"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FallenMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_12_1 = "minerfinalbot" ascii //weight: 12
        $x_8_2 = {3b 37 e0 ff 48 8d 0d f4 ef 01 00 48 89 4c 24 50 48 89 44 24 58 48 8d 05 78 cd 07 00 bb 0b 00 00 00 bf 01}  //weight: 8, accuracy: High
        $x_2_3 = {48 8b 4c 24 30 48 85 c9 0f 85 36 ?? ?? ?? 48 8b 44 24 48 48 8b 5c 24 28 0f 1f 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


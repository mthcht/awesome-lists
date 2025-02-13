rule Trojan_Win64_CobaltStrikeWinGo_DY_2147909092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikeWinGo.DY!MTB"
        threat_id = "2147909092"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikeWinGo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 88 4c 30 ff 48 ff c1 4c 89 c7 48 39 cb 7e ?? 4c 8d 47 01 44 0f b6 0c 08 44 0f b6 54 24 ?? 45 31 ca 44 0f b6 4c 24 ?? 45 31 d1 4c 39 c2 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


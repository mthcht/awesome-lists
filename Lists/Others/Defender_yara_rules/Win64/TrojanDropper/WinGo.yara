rule TrojanDropper_Win64_WinGo_AMCN_2147927130_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/WinGo.AMCN!MTB"
        threat_id = "2147927130"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "WinGo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 88 54 01 ff 48 ff c6 4c 89 d8 4c 89 e2 48 39 f3 0f 8e ?? ?? ?? ?? 44 0f b6 14 30 48 85 c9 0f 84 ?? ?? ?? ?? 49 89 c3 48 89 f0 49 89 d4 48 99 48 f7 f9 48 39 ca 73 ?? 49 ff c1 42 0f b6 14 22 41 31 d2 4c 39 cf 73 ?? 48 89 74 24 ?? 44 88 54 24 ?? 4c 89 c0 4c 89 cb 48 89 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


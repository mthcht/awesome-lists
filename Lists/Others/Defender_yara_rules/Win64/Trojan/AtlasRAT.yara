rule Trojan_Win64_AtlasRAT_SX_2147966464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AtlasRAT.SX!MTB"
        threat_id = "2147966464"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AtlasRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 7b 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2d 00 46 00 55 00 43 00 4b 00 2d 00 ?? ?? ?? ?? ?? ?? ?? ?? 2d 00 43 00 4c 00 4f 00 53 00 45 00 2d 00}  //weight: 20, accuracy: Low
        $x_20_2 = {47 6c 6f 62 61 6c 5c 7b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2d 46 55 43 4b 2d ?? ?? ?? ?? ?? ?? ?? ?? 2d 43 4c 4f 53 45 2d}  //weight: 20, accuracy: Low
        $x_10_3 = "$action = New-ScheduledTaskAction -Execute $obfuscatedPath;" ascii //weight: 10
        $x_5_4 = "/c ping -n 2 127.0.0.1 > nul && del" ascii //weight: 5
        $x_3_5 = "Wxfun.dll" ascii //weight: 3
        $x_2_6 = "Atlas" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}


rule Trojan_Win32_Ghostsocks_AGS_2147954916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ghostsocks.AGS!MTB"
        threat_id = "2147954916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ghostsocks"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 3c b2 0f b6 3f 89 3c b0 8d 6e 01 39 cd 7d ?? 89 ee c1 e5 02 39 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ghostsocks_AGH_2147956887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ghostsocks.AGH!MTB"
        threat_id = "2147956887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ghostsocks"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 c1 ea 03 83 c2 30 66 89 56 14 33 d2 0f b7 47 02 f7 f3 b8 cd ?? ?? ?? 83 c2 30 66 89 56 16 0f b7 4f 06 f7 e1 c1 ea 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


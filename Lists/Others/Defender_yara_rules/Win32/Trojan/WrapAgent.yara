rule Trojan_Win32_WrapAgent_AF_2147768550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WrapAgent.AF!MTB"
        threat_id = "2147768550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WrapAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c8 89 ?? dc 8d 85 ?? ?? ?? ?? 0f b7 c8 b8 ?? ?? ?? ?? f7 e9 c1 fa ?? 8b fa c1 ef ?? 8b ?? dc 03 c2 03 f8 8b 85 ?? ?? ?? ?? 0f b7 c0 2b f8 2b 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WrapAgent_AX_2147772098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WrapAgent.AX!MTB"
        threat_id = "2147772098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WrapAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 1f 00 8a 44 0f ?? 32 c3 2a c3 32 c7 88 04 31 41 3b ca 7c ?? 5f [0-16] 5e 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 49 01 f7 e7 c1 ea ?? 8d 04 92 03 c0 2b f8 8b c7 8b fa 04 ?? 88 44 ?? ff 85 ff 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


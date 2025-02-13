rule Trojan_Win32_Cidox_GNN_2147932766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cidox.GNN!MTB"
        threat_id = "2147932766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cidox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 00 88 45 e4 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8a 00 32 45 e4 8b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 88 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


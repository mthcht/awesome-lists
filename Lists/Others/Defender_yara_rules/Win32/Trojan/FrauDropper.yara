rule Trojan_Win32_FrauDropper_NF_2147909805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FrauDropper.NF!MTB"
        threat_id = "2147909805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FrauDropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {89 44 24 7c 66 8b 8c 24 ?? ?? ?? ?? 66 89 8c 24 ?? ?? ?? ?? 8b 84 24 9c 00 00 00 69 94 24 98 00 00 00 ?? ?? ?? ?? 01 d0 8b 40 4c 89 84 24 ?? ?? ?? ?? 8b 84 24 98 00 00 00 69 c0}  //weight: 3, accuracy: Low
        $x_3_2 = {83 ec 0c 0f b7 84 24 ?? ?? ?? ?? 09 c0 66 89 c6 66 89 b4 24}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


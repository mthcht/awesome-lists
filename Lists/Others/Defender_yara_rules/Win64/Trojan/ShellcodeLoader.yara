rule Trojan_Win64_ShellcodeLoader_MKV_2147942741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeLoader.MKV!MTB"
        threat_id = "2147942741"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 1e 32 18 48 8b 95 58 02 00 00 48 83 ec 20 48 89 f9 e8 12 a3 00 00 48 83 c4 20 88 18 48 8b 9d ?? ?? ?? ?? 48 83 c3 01 b8 56 e9 d3 fd 3d e3 8d 0c 15 0f 8e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


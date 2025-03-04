rule Trojan_Win32_ChePro_AB_2147849709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ChePro.AB!MTB"
        threat_id = "2147849709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ChePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c0 89 45 98 8b 45 ec 8b 55 d4 01 02 8b 45 c4 03 45 ?? 03 45 ec 03 45 98 89 45 a4 6a 00 e8 ?? ?? ?? ?? 8b 5d a4 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d4 31 18 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72 9f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


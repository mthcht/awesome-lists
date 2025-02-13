rule Trojan_Win32_CobaltStrikeLoader_AA_2147816049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrikeLoader.AA!MTB"
        threat_id = "2147816049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrikeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 56 57 e8 ?? ?? ff ff 6a 00 6a 00 68 00 00 04 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 ec ec ?? ?? ?? c7 45 f0 14 ?? ?? ?? c7 45 f4 3c ?? ?? ?? c7 45 f8 64 ?? ?? ?? c7 45 fc 8c ?? ?? ?? ff 15 ?? ?? ?? ?? 68 00 00 10 00 6a 00 50 ff 15 ?? ?? ?? ?? 8b d8 33 f6 8b fb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


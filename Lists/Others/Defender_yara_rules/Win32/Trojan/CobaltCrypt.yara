rule Trojan_Win32_CobaltCrypt_VC_2147760076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltCrypt.VC!MTB"
        threat_id = "2147760076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 00 31 0d ?? ?? ?? ?? c7 05 [0-64] a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b ff a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 1, accuracy: Low
        $x_1_2 = {89 08 5f 5d 28 00 31 0d ?? ?? ?? ?? c7 05 [0-64] a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b ff a1 ?? ?? ?? ?? 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


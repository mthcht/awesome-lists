rule Trojan_Win32_GhostRatCrypt_GA_2147775701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GhostRatCrypt.GA!MTB"
        threat_id = "2147775701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GhostRatCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {40 33 ff 89 45 ?? 57 8a 04 10 8a 14 0e 32 d0 88 14 0e ff 15 ?? ?? ?? ?? 8b c6 b9 ?? ?? ?? ?? 99 f7 f9 85 d2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


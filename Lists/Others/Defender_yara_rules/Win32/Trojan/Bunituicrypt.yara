rule Trojan_Win32_Bunituicrypt_RT_2147793936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunituicrypt.RT!MTB"
        threat_id = "2147793936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunituicrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 8b 45 ?? 8b 00 03 45 ?? 03 d8 e8 ?? ?? ?? ?? 2b ?? 8b 45 ?? 89 18 8b 45 ?? 03 45 ?? 2d 67 2b 00 00 03 45 ?? 8b 55 ?? 31 02 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


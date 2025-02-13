rule Trojan_Win32_Povertystealer_ASK_2147931445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Povertystealer.ASK!MTB"
        threat_id = "2147931445"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Povertystealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 c1 83 e1 1f 0f b6 89 ?? ?? ?? 00 30 0c 06 40 3d ?? ?? ?? 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_BilhanStealer_ABH_2147958888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BilhanStealer.ABH!MTB"
        threat_id = "2147958888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BilhanStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 18 62 40 00 68 0c 62 40 00 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b d0 b9 0e 00 00 00 33 c0 8d 7c 24 08 f3 ab 8b 44 24 44 8d 4c 24 04 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


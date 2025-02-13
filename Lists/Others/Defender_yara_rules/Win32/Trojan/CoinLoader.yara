rule Trojan_Win32_CoinLoader_SM_2147761707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CoinLoader.SM!MTB"
        threat_id = "2147761707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 18 00 00 00 56 33 f6 8b 40 30 8b 40 0c 8b 40 0c 8b 08 85 c9 74}  //weight: 1, accuracy: High
        $x_1_2 = {8a 1a 8d 43 ?? 3c ?? 77 03 80 c3 ?? 0f be c3 83 c2 ?? 33 f8 c1 c7 0d 47 66 39 32 75 ?? 81 ff ?? ?? ?? ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


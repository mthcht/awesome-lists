rule Trojan_Win64_Reverseshell_RP_2147907293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Reverseshell.RP!MTB"
        threat_id = "2147907293"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Reverseshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 00 00 48 8b 05 ?? ?? 00 00 48 89 85 ?? ?? 00 00 48 8b 05 ?? ?? 00 00 48 89 85 ?? ?? 00 00 48 8b 05 ?? ?? 00 00 48 89 85 ?? ?? 00 00 48 8b 05 ?? ?? 00 00 48 89 85 ?? ?? 00 00 48 b8 63 6d 64 2e 65 78 65 00 48 89 85 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


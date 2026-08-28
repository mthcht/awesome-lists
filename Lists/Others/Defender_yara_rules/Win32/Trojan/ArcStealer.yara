rule Trojan_Win32_ArcStealer_C_2147977186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ArcStealer.C!MTB"
        threat_id = "2147977186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ArcStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 cb e9 05 00 00 00 e9 ?? ?? ?? ?? 01 df 81 c7 ?? ?? ?? ?? e9 ?? 00 00 00 81 c3 ?? ?? ?? ?? 39 df c7 44 24 04 ?? ?? ?? ?? 0f 92 44 24 03 e9 ?? ?? ?? ?? 85 c0 bf ?? ?? ?? ?? 0f 44 fe 89 7c 24 04 c6 44 24 03 00 e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


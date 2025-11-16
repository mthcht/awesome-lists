rule Trojan_Win32_Gulpix_AHB_2147957565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gulpix.AHB!MTB"
        threat_id = "2147957565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gulpix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {c6 85 b6 fe ff ff 33 c6 85 b7 fe ff ff 69 c6 85 b8 fe ff ff 53 c6 85 b9 fe ff ff 63 c6 85 ba fe ff ff 78 c6 85 bb fe ff ff 21}  //weight: 30, accuracy: High
        $x_20_2 = {0f b6 c8 81 e1 ?? ?? ?? ?? 0f b6 d1 0f b6 45 ed c1 f8 ?? 0f b6 c8 83 e1 ?? 0f b6 c1 0b d0 8b 4d 0c}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Psaruaa_YAC_2147936400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Psaruaa.YAC!MTB"
        threat_id = "2147936400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Psaruaa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 f7 b5 bc 9a ff ff 0f b6 92 00 00 42 00 33 ca 8b 85 ec ?? ff ff 88 8c 05 f8 d6 ff ff eb b3}  //weight: 10, accuracy: Low
        $x_6_2 = {0f b6 92 00 00 42 00 33 ca 8b 85 b8 ?? ff ff 03 85 e8 9a ff ff 88 08}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


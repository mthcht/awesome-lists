rule Trojan_Win32_Miancha_JHAA_2147906236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miancha.JHAA!MTB"
        threat_id = "2147906236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miancha"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {99 f7 f9 8b 45 f4 89 55 ?? 8d 0c 32 8a 14 32 88 10 8b 55 ?? 88 19 8b 4d ?? 0f b6 00 03 ca 0f b6 d3 03 c2 8b df 99 f7 fb 8a 04 32 30 01 ff 45 fc 8b 45 fc 3b 45 10 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_DBatLoader_MKZ_2147933327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DBatLoader.MKZ!MTB"
        threat_id = "2147933327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DBatLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 db 8b 45 f8 0f b6 04 18 8b 55 f0 32 04 1a 8b 55 ?? 88 04 1a 43 83 fb 30 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_MedusaLocker_WZV_2147958820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MedusaLocker.WZV!MTB"
        threat_id = "2147958820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MedusaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c4 04 81 e3 a0 eb 00 00 81 eb 8e 1d 01 00 81 c3 69 cb 00 00 5b 8b 8d f4 f4 ff ff 89 8d 54 e2 ff ff c7 85 ?? ?? ff ff 00 00 00 00 eb 0f 8b 95 ?? ?? ff ff 83 c2 01 89 95 60 f9 ff ff 8b 85 60 f9 ff ff 3b 85 7c f4 ff ff 73 50 8b 8d 54 e2 ff ff 03 8d ?? ?? ff ff 8b 95 50 e2 ff ff 03 95 ?? ?? ff ff 8a 02 88 01 56 81 f6 fc 07 01 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


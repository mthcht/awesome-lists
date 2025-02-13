rule Trojan_Win32_Terraloader_LKA_2147848793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Terraloader.LKA!MTB"
        threat_id = "2147848793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Terraloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 5d 24 89 5c 24 14 8b 5c 24 68 8b 6c 24 0c 03 5d 20 89 5c 24 18 8b 6c 24 0c 8b 5d 18 81 fb 00 10 00 00 7f 0d}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 10 00 00 00 00 eb 00 b8 10 27 00 00 3b 44 24 ?? 0f 8c 8c 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


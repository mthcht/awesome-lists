rule Trojan_Win32_TerraCrypt_LKB_2147848798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TerraCrypt.LKB!MTB"
        threat_id = "2147848798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TerraCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 8b 5c 24 08 8b 6c 24 ?? 01 db 58 66 89 44 1d 00 8b 5c 24 ?? 43 89 5c 24 ?? 8b 5c 24 ?? 43 89 5c 24 ?? 8b 5c 24 ?? 3b 5c 24 ?? 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


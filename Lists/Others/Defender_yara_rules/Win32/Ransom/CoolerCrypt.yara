rule Ransom_Win32_CoolerCrypt_MKV_2147892454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CoolerCrypt.MKV!MTB"
        threat_id = "2147892454"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CoolerCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c9 0f b6 89 f0 70 45 00 33 04 cd 72 2c 47 00 8b 4d ec 8b 55 fc 8b 4c 8a ?? c1 e9 00 0f b6 c9 0f b6 89 f0 70 45 00 33 04 cd 73 2c 47 00 8b 4d f8 8b 55 fc 89 44 8a ?? 8b 45 ec 8b 4d fc 8b 55 f0 89 54 81 0c e9}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 08 89 45 cc 8b 45 cc 8b 4d e0 33 0c c5 ?? ?? ?? ?? 89 4d e0 8b 45 c8 83 c0 20 89 45 c8 8b 45 b4 48 89 45 b4 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


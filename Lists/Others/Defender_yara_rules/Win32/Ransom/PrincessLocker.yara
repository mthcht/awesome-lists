rule Ransom_Win32_PrincessLocker_A_2147723373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/PrincessLocker.A"
        threat_id = "2147723373"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "PrincessLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 fc 02 8d 45 ?? 83 7d ?? 10 0f 43 45 ?? 50 53 ff 15 ?? ?? ?? ?? 68 00 00 00 f0 6a 18 68 ?? ?? ?? ?? 6a 00 8b f8 68 ?? ?? ?? ?? ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = {3a 00 5c 00 50 ff 15 ?? ?? ?? ?? 83 f8 03 74 09 83 f8 04 0f 85 ?? ?? 00 00 6a 00 6a 00 6a 00 6a 00 8d 45 e4 50 ff 15 ?? ?? ?? ?? 85 c0 0f 84}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c3 1a 83 c0 1a 89 9d ?? ?? ff ff 89 85 ?? ?? ff ff 81 fb 46 9a 00 00 0f 82 ?? ?? ff ff 8b 85 ?? ?? ff ff 83 f8 08 72 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Ransom_Win32_RagnarLockerCrypt_DA_2147764053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RagnarLockerCrypt.DA!MTB"
        threat_id = "2147764053"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RagnarLockerCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 a4 83 c2 01 89 55 a4 81 7d a4 ?? ?? 00 00 0f 83 ?? ?? ?? ?? 8b 45 a4 8b 4d b4 8b 14 81 89 95 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8b 8d 02 2b 4d a4 89 8d 02 8b 55 c4 c1 e2 ?? 89 55 c4 8b 85 02 33 85 04 89 85 02 8b 4d c4 81 c1 ?? ?? ?? ?? 89 4d c4 c1 85 02 ?? 8b 45 c4 99 81 e2 ?? ?? ?? 00 03 c2 c1 f8 ?? 89 45 c4 8b 95 02 33 95 04 89 95 02 8b 45 a4 8b 4d ec 8b 95 02 89 14 81 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


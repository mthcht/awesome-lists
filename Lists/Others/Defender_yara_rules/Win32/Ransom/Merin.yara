rule Ransom_Win32_Merin_MB_2147765670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Merin.MB!MTB"
        threat_id = "2147765670"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Merin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c8 0f b6 45 ff 8a 80 ?? ?? ?? ?? 88 45 fd 0f b6 45 fe 8a 80 00 88 45 ff 0f b6 45 fc 8a 80 00 88 45 fe 8b c3 c1 e8 ?? 8a a0 ?? ?? ?? ?? 32 a1 00 8a 4d ff 8a 6d fe 8a 42 f3 43 32 c4 88 42 03 8a 42 f4 32 45 fd 88 42 04 8a 42 f5 32 c1 88 42 05 8a 42 f6 32 c5 88 42 06 83 c2 ?? 83 fb ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = "MERIN-DECRYPTING.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


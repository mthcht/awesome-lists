rule Ransom_Win32_NokonokoPacker_ZC_2147844142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/NokonokoPacker.ZC!MTB"
        threat_id = "2147844142"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "NokonokoPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 1c 02 8b 55 ?? 8b 45 ?? 01 d0 0f b6 30 8b 4d ?? ba ?? ?? ?? ?? 89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 c1 e0 02 01 d0 c1 e0 ?? 01 d0 29 c1 89 ca 8b 45 ?? 01 d0 0f b6 00 31 f0 88 03 83 45 ?? ?? 8b 55 ?? 8b 45 ?? 39 c2 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Ransom_Win32_BazarLoader_2147812315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BazarLoader!MTB"
        threat_id = "2147812315"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c9 8a 84 0d 3b ff ff ff 0f b6 c0 83 e8 60 8d 04 c0 99 f7 fb 8d 42 7f 99 f7 fb 88 94 0d 3b ff ff ff 41 83 f9 52 72 da 6a 00 8d 85 34 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


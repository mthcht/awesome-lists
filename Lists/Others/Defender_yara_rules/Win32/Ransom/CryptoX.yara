rule Ransom_Win32_CryptoX_PA_2147975227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CryptoX.PA!MTB"
        threat_id = "2147975227"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptoX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 05 40 30 ?? 6d 0f b6 10 0f b6 05 c0 30 ?? 6d 31 c2 8b 45 f4 05 40 30 ?? 6d 88 10 8b 45 f4 05 80 30 ?? 6d 0f b6 10 0f b6 05 c1 30 ?? 6d 31 c2 8b 45 f4 05 80 30 ?? 6d 88 10 83 45 f4 01 83 7d f4 3f 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


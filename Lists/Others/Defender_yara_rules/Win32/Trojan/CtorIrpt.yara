rule Trojan_Win32_CtorIrpt_AD_2147744574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CtorIrpt.AD!MTB"
        threat_id = "2147744574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CtorIrpt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fc ff ff 56 c6 85 ?? fc ff ff 69 c6 85 ?? fc ff ff 72 c6 85 ?? fc ff ff 74 c6 85 ?? fc ff ff 75 c6 85 ?? fc ff ff 61 c6 85 ?? fc ff ff 6c c6 85 ?? fc ff ff 41 c6 85 ?? fc ff ff 6c c6 85 ?? fc ff ff 6c c6 85 ?? fc ff ff 6f c6 85 ?? fc ff ff 63 c6 85 ?? fc ff ff 00}  //weight: 1, accuracy: Low
        $x_1_2 = {64 a1 00 00 00 00 50 81 ec ?? ?? 00 00 a1 ?? ?? ?? ?? 33 c5 89 45 ?? 50 8d 45 ?? 64 a3 00 00 00 00 b9 ?? ?? ?? ?? e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


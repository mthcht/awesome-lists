rule Trojan_Win32_Spyder_LKV_2147897410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spyder.LKV!MTB"
        threat_id = "2147897410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spyder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {df ff ff 8b 0d ?? ?? ?? ?? 32 04 3e 88 04 0e 46 3b f3 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 84 0d e0 df ff ff 88 04 0f 83 c1 01 83 d2 00 75 05 83 f9 0e 72 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


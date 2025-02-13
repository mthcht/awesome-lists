rule Trojan_Win32_Avemariarat_VU_2147758817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Avemariarat.VU!MTB"
        threat_id = "2147758817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Avemariarat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 99 f7 bd ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8b 55 ?? 03 55 ?? 0f be 02 8b 8d ?? ?? ?? ?? 0f be 54 0d ?? 33 c2 8b 4d ?? 03 4d ?? 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


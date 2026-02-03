rule Trojan_Win32_GCLeaner_ZXC_2147962262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GCLeaner.ZXC!MTB"
        threat_id = "2147962262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GCLeaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 d0 03 55 9c 52 6a 00 e8 ?? ?? ?? ?? 5a 2b d0 52 6a 00 e8 ?? ?? ?? ?? 5a 03 d0 31 13 83 c6 04 83 c3 04 3b 75 d0 0f 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


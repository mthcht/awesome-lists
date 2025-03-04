rule Trojan_Win32_StealBit_MP_2147896995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StealBit.MP!MTB"
        threat_id = "2147896995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StealBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 8b c1 83 e0 0f 8a 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 83 f9 7c 72 e9 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


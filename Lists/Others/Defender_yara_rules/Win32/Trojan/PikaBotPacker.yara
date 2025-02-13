rule Trojan_Win32_PikaBotPacker_SU_2147893666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PikaBotPacker.SU!MTB"
        threat_id = "2147893666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PikaBotPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 1a 03 5d ?? 2b d8}  //weight: 1, accuracy: Low
        $x_1_2 = {03 d8 8b 45 ?? 89 18}  //weight: 1, accuracy: Low
        $x_1_3 = {2b d8 8b 45 ?? 31 18}  //weight: 1, accuracy: Low
        $x_1_4 = {2b d8 01 5d ?? 8b 45 ?? 3b 45 ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


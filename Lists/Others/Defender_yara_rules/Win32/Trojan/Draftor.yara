rule Trojan_Win32_Draftor_GVA_2147976397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Draftor.GVA!MTB"
        threat_id = "2147976397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Draftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 10 8b 45 f0 83 e0 3f 0f b6 80 [0-4] 31 c2 8b 45 f0 05 [0-4] 88 10 83 45 f0 01 a1 [0-4] 39 45 f0 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Prometei_CCIR_2147936494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Prometei.CCIR!MTB"
        threat_id = "2147936494"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Prometei"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d9 02 da 30 18 85 c9 74 ?? 40 8d 98 ?? ?? ?? ?? 49 03 d7 3b de 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


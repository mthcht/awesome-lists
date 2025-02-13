rule Trojan_Win32_Baldr_AD_2147735055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Baldr.AD!MTB"
        threat_id = "2147735055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Baldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf 33 d2 6a ?? 8b c1 5e f7 f6 8a 44 15 ?? 30 81 ?? ?? ?? ?? 41 81 f9 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = "av4.0.30319" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


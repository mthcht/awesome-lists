rule Trojan_Win32_Fattura_YSN_2147972356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fattura.YSN!MTB"
        threat_id = "2147972356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fattura"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {33 d2 30 81 ?? ?? ?? ?? 8d 41 01 f7 f6 0f b6 04 17 33 d2 30 81 ?? ?? ?? ?? 8d 41 02 f7 f6 0f b6 04 17 33 d2 30 81 ?? ?? ?? ?? 8d 41 03}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


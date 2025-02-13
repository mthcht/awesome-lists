rule Trojan_Win32_Vidarstealer_MA_2147761925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vidarstealer.MA!MTB"
        threat_id = "2147761925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidarstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 88 f8 30 d8 88 c7 88 3f 58 8b 5c 24 ?? 43 89 5c 24 00 8b 5c 24 00 3b 5c 24 ?? 7e 08 c7 44 24 00 ?? ?? ?? ?? ff 44 24 ?? 71 95}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Stelac_LK_2147847099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stelac.LK!MTB"
        threat_id = "2147847099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stelac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c0 e3 04 c0 e8 02 0a c3 88 [0-19] 8a 9b ?? ?? ?? ?? c0 e3 06 0a 98 ?? ?? ?? ?? 83 c6 04 88 59 ?? 83 c1 03 3b ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Ferro_RM_2147908628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ferro.RM!MTB"
        threat_id = "2147908628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ferro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 8a 45 0c 8a 4d 08 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


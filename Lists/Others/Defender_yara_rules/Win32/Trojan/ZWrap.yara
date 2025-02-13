rule Trojan_Win32_ZWrap_AB_2147767065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZWrap.AB!MTB"
        threat_id = "2147767065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZWrap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 8a 0c 02 8b 44 ?? ?? 8b 7c ?? ?? 30 0c 38 40 3b 44 ?? ?? 89 44 ?? ?? 0f [0-6] 8b 44 ?? ?? 8a 54 ?? ?? 8a 4c ?? ?? 5f 5e 5d [0-16] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


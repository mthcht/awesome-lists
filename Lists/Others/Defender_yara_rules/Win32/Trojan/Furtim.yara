rule Trojan_Win32_Furtim_A_2147711966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Furtim.A"
        threat_id = "2147711966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Furtim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 3a cb 74 30 8b 45 ?? 8a 80 ?? ?? ?? ?? 88 45 ?? 8a 45 ?? f6 ea 02 c1 30 45 ?? 8a 8a ?? ?? ?? ?? 42 3a cb 75 eb 8a 45 ?? 8b 4d ?? 88 81 ?? ?? ?? ?? 8b 45 ?? ff 45 ?? 39 45 ?? 72 bc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


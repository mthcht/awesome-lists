rule Trojan_Win32_WinDealer_LAX_2147840118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinDealer.LAX!MTB"
        threat_id = "2147840118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinDealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 33 d2 f7 f3 8a 44 14 ?? 8a 14 29 32 d0 88 14 29 41 3b ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_WinDealer_HYD_2147840119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WinDealer.HYD!MTB"
        threat_id = "2147840119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WinDealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 33 d2 bb ?? ?? ?? ?? f7 f3 8a 1c 31 8b 44 24 ?? 8a 54 3a ?? 32 da 88 1c 31 41 3b c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


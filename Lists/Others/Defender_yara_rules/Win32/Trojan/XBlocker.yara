rule Trojan_Win32_XBlocker_FVD_2147964604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XBlocker.FVD!MTB"
        threat_id = "2147964604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XBlocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b fa c1 e7 ?? 0b fa 66 31 38 41 38 99 ?? ?? ?? ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


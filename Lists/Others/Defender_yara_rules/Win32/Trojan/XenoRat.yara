rule Trojan_Win32_XenoRat_AXNR_2147945241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XenoRat.AXNR!MTB"
        threat_id = "2147945241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XenoRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d2 f7 f6 0f be 35 ?? ?? ?? ?? 89 ca 39 f0 74 ?? f2 0f 10 74 24 08 0f be 05 ?? ?? ?? ?? 83 c0 07 0f be 0d ?? ?? ?? ?? 31 d2 f7 f1 0f be 0d ?? ?? ?? ?? 29 c8 66 0f 6e f8 66 0f eb f9 f2 0f 5c fa f2 0f 59 fe f2 0f 2c d7 21 da 03 7c 24 04 01 d2 29 d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


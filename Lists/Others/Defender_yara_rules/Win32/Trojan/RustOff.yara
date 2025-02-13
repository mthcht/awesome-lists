rule Trojan_Win32_RustOff_LKA_2147899307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RustOff.LKA!MTB"
        threat_id = "2147899307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RustOff"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 27 77 ?? 8b 91 ?? ?? ?? 00 33 14 08 89 94 0c ?? ?? 00 00 83 c1 04 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


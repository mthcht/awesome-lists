rule Trojan_Win32_SilverFox_ISR_2147947869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SilverFox.ISR!MTB"
        threat_id = "2147947869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SilverFox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 cd cc cc cc f7 e1 c1 ea 02 8d 04 92 8b d1 2b d0 8a 86 c0 6f 4d 00 02 82 b8 6f 4d 00 02 c1 41 30 07 83 f9 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


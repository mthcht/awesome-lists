rule Trojan_Win32_Mucc_AN_2147837902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mucc.AN!MTB"
        threat_id = "2147837902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mucc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 10 a7 38 08 00 2b 33 71 b5 aa 4b d3 a4 88 e3 0c 4a bd 18 fa d2 15 [0-4] 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 7b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


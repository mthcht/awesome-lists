rule Trojan_Win32_Raccoonstlr_GG_2147759127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoonstlr.GG!MTB"
        threat_id = "2147759127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoonstlr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f3 33 75 [0-2] 2b fe 25 [0-4] 81 6d [0-5] bb [0-4] 81 45 [0-5] 8b 4d [0-2] 83 25 [0-4] 00 8b c7 d3 e0 8b cf c1 e9 [0-2] 03 4d [0-2] 03 45 [0-2] 33 c1 8b 4d [0-2] 03 cf 33 c1 [0-32] 8d 45 [0-2] e8 [0-4] ff 4d [0-2] 0f 85 [0-100] 89 7e [0-2] 5f 5e 5b c9 [0-100] 83 c6 [0-2] 4f 75}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 a1 [0-4] 8b 15 [0-4] 89 45 [0-2] b8 [0-4] 01 45 [0-2] 8b 45 [0-2] 8a 04 [0-2] 88 04 [0-2] c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


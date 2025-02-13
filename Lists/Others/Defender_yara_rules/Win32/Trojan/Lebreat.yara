rule Trojan_Win32_Lebreat_HNA_2147907992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lebreat.HNA!MTB"
        threat_id = "2147907992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lebreat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 07 00 00 00 89 d1 99 f7 f9 83 fb 0b 7f ?? 0f b6 44 2b c4 88 04 3a 83 fb 14 7e ?? 0f b6 44 2b c4 88 04 3a 4e}  //weight: 1, accuracy: Low
        $x_1_2 = {55 89 e5 83 ec ?? c7 04 24 ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


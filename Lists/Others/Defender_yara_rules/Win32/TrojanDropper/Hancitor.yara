rule TrojanDropper_Win32_Hancitor_ARA_2147847113_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Hancitor.ARA!MTB"
        threat_id = "2147847113"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Hancitor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 8d 14 80 03 d2 8b c1 2b c2 8a ?? ?? ?? ?? ?? 30 14 0e 41 3b 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


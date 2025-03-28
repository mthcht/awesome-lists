rule TrojanDropper_Win32_Necurs_EAE_453618_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Necurs.EAE!MTB"
        threat_id = "453618"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Necurs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 4d a4 c1 45 a4 0b 8b 55 a4 33 15 ?? ?? ?? ?? 89 55 a4 8b 45 e8 8b 4d f8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


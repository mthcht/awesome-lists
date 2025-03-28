rule TrojanDropper_Win32_Rhadamanthys_EA_2147937248_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rhadamanthys.EA!MTB"
        threat_id = "2147937248"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 98 48 89 45 98 8d 97 ?? ?? ?? ?? 66 89 15 ?? ?? ?? ?? 66 89 4d a8 8a 14 1e 88 13}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


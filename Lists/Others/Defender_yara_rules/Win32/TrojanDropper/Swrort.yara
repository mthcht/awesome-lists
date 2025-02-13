rule TrojanDropper_Win32_Swrort_ASW_2147896764_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Swrort.ASW!MTB"
        threat_id = "2147896764"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Swrort"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 fc c7 44 24 ?? ?? ?? ?? ?? 8b 45 fc 89 04 24 e8 2b 06 00 00 83 ec 08 c7 45 f8 ?? ?? ?? ?? c7 44 24 04}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 f8 89 44 24 08 c7 44 24 04 ec 79 49 00 8b 45 f4 89 04 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


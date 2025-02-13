rule Trojan_Win32_Squirelwaffle_PA_2147795977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Squirelwaffle.PA!MTB"
        threat_id = "2147795977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Squirelwaffle"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "start /i /min /b start /i /min /b start /i /min /b" ascii //weight: 1
        $x_1_2 = "\\Dll1.pdb" ascii //weight: 1
        $x_2_3 = {33 d2 c7 45 dc 00 00 00 00 8b c7 c7 45 e0 ?? 00 00 00 f7 75 30 83 7d 1c ?? 8d 4d ?? 8d 45 ?? c6 45 ?? 00 0f 43 4d ?? 83 7d 34 ?? 0f 43 45 20 8a 04 10 32 04 39 8d 4d cc 0f b6 c0 50 6a 01 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


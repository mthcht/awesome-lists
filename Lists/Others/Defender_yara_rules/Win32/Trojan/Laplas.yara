rule Trojan_Win32_Laplas_PA_2147845616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Laplas.PA!MTB"
        threat_id = "2147845616"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Laplas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 24 89 44 24 1c 8b 44 24 20 01 44 24 1c 8b 4c 24 14 8b c6 d3 e8 8b 4c 24 30 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 24 8d 44 24 24 e8 ?? ?? ?? ?? 8b 44 24 1c 31 44 24 10 81 3d dc 8b b9 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


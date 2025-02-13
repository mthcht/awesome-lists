rule Virus_Win32_Senoval_HNS_2147905678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Senoval.HNS!MTB"
        threat_id = "2147905678"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Senoval"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec 81 ec ?? 00 00 00 60 e8 00 00 00 00 8f 85 [0-18] 29 85}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 40 68 00 10 00 00 68 ?? ?? ?? ?? 6a 00}  //weight: 2, accuracy: Low
        $x_2_3 = {ff d3 c9 c3 06 00 03 8d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


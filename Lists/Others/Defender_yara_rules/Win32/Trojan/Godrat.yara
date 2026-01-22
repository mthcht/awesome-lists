rule Trojan_Win32_Godrat_AGR_2147961637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Godrat.AGR!MTB"
        threat_id = "2147961637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Godrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 3d 10 f0 40 00 68 ?? 3d 41 00 56 ff d7 68 ?? 3d 41 00 56 89 44 24 20 ff d7 68 ?? 3d 41 00 56 89 44 24 3c ff d7 68 ?? 3d 41 00 56 89 44 24 1c ff d7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Ransom_Win32_Babar_YAA_2147903318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Babar.YAA!MTB"
        threat_id = "2147903318"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af dd c1 c3 05 89 4c 24 ?? 8a ca d3 ce 8a cb 33 f3 d3 cf 33 fa 8b cf 8b d5 8b ee}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


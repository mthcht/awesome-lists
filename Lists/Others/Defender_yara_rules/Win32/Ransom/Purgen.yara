rule Ransom_Win32_Purgen_SR_2147966651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Purgen.SR!MTB"
        threat_id = "2147966651"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Purgen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 30 b8 ?? ?? ?? ?? 2b c7 03 f0 8d 46 ?? 0f af 44 24 ?? 6b c0 ?? 03 c7 30 04 0a 8b 54 24 ?? 0f af d7 69 d2 ?? ?? ?? ?? bf ?? ?? ?? ?? 2b fa 0f af f7 8b 7c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


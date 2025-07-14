rule Ransom_Win64_Fog_AHB_2147946217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Fog.AHB!MTB"
        threat_id = "2147946217"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Fog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {65 48 8b 04 25 60 00 00 00 48 89 44 24 08 48 8b 44 24 08 0f b6 40 02 85 c0 74 ?? c7 04 24 01 00 00 00 eb ?? c7 04 24}  //weight: 2, accuracy: Low
        $x_1_2 = "\\RANSOMNOTE.txt" ascii //weight: 1
        $x_1_3 = "OBSIDIANMIRROR - PSYOPS/PSYWAR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


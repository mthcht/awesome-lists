rule HackTool_Win64_Sucipik_MBWQ_2147931796_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Sucipik.MBWQ!MTB"
        threat_id = "2147931796"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Sucipik"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b d0 44 89 7c 24 40 48 8d 85 d8 04 00 00 c7 44 24 38 02 00 00 00 45 33 c9 48 89 44 24 30 4c 89 7c 24 28 4c 89 7c 24 20 ff ?? 44 8b 85 98 02 00 00 33 d2 b9 ff ff 1f 00 ff ?? c4 cd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


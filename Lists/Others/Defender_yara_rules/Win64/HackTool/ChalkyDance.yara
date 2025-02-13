rule HackTool_Win64_ChalkyDance_A_2147932406_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/ChalkyDance.A!dha"
        threat_id = "2147932406"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ChalkyDance"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4c 8b 40 30 ba ?? 00 00 00 b9 40 00 00 00 41 ff d0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


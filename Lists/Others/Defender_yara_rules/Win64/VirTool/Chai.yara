rule VirTool_Win64_Chai_A_2147907236_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Chai.A"
        threat_id = "2147907236"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Chai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b ce ff ?? ?? ?? ?? ?? 48 8b 55 f7 ?? ?? ?? ?? ?? ?? ?? 44 8b c0 ?? ?? ?? ?? ?? 48 8b 55 f7 45 33 c9 45 33 c0 4c 89 7c 24 20 48 8b ce}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 4c 24 08 48 89 54 24 10 4c 89 44 24 18 4c 89 4c 24 20 53 56 57 48 83 ec 30 48 8b f9}  //weight: 1, accuracy: High
        $x_1_3 = {48 89 5c 24 38 44 8d 43 50 89 5c 24 30 ?? ?? ?? ?? ?? ?? ?? c7 44 24 28 03 00 00 00 45 33 c9 48 8b c8 48 89 5c 24 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


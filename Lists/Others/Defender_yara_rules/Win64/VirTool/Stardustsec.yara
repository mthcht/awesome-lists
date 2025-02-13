rule VirTool_Win64_Stardustsec_A_2147924609_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Stardustsec.A"
        threat_id = "2147924609"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Stardustsec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 48 89 e6 48 83 e4 f0 48 83 ec 20 e8 ?? ?? ?? ?? 48 89 f4 5e c3 e8 ?? ?? ?? ?? c3 48 8b 04 24 48 83 e8 1b c3}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 04 24 48 83 c0 0b c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule VirTool_Win64_Angomod_A_2147734169_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Angomod.A"
        threat_id = "2147734169"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Angomod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 ea 00 20 22 00 74 1a 83 fa 04 74 07 48 83 67 38 00}  //weight: 1, accuracy: High
        $x_1_2 = {b9 80 25 00 00 66 39 08 73 09 48 8b bf 90 03 00 00 eb 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


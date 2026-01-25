rule HackTool_Win64_InfestedShuttle_A_2147961709_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/InfestedShuttle.A!dha"
        threat_id = "2147961709"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "InfestedShuttle"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "agent.exe 192.168.1.100:12345" ascii //weight: 1
        $x_1_2 = {6d 61 69 6e 2e 72 65 61 64 53 68 61 6b 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {6d 61 69 6e 2e 43 6c 69 65 6e 74 53 68 61 6b 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


rule HackTool_Win64_XBack_A_2147928527_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/XBack.A"
        threat_id = "2147928527"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "XBack"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "exe <addr:port> <BotId_32chars> <tag=scheme://dest>" ascii //weight: 1
        $x_1_2 = {43 61 6e 27 74 20 70 61 72 73 65 20 3c 72 6f 75 74 65 72 5f 69 70 3a 70 6f 72 74 3e 0a 00 00 00 43 61 6e 27 74 20 70 61 72 73 65 20 65 6e 64 70 6f 69 6e 74 20 2d 20 27 25 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win64_XBack_B_2147928528_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/XBack.B"
        threat_id = "2147928528"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "XBack"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 32 37 2e 30 2e 30 2e 31 00 00 00 63 6d 64 00 70 6f 77 65 72 73 68 65 6c 6c 00 00 3d 00 00 00 2d 2d ?? ?? ?? ?? ?? ?? 62 6f 74 5f 73 65 72 76 65 72 20 3c 73 65 72 76 65 72 3a 70 6f 72 74 3e 20 3c 75 75 69 64 3e 2e 20 0a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


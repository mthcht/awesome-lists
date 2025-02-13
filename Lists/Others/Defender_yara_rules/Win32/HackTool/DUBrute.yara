rule HackTool_Win32_DUBrute_A_2147684700_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DUBrute.A"
        threat_id = "2147684700"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DUBrute"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 50 61 73 73 77 6f 72 64 5d [0-16] 5b 4c 6f 67 69 6e 5d [0-16] 25 75 73 65 72 6e 61 6d 65 25}  //weight: 1, accuracy: Low
        $x_1_2 = "PushAddPass()" ascii //weight: 1
        $x_1_3 = "DUBrute_v" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


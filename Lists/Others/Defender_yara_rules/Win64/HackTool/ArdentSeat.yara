rule HackTool_Win64_ArdentSeat_A_2147961708_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/ArdentSeat.A!dha"
        threat_id = "2147961708"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ArdentSeat"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "x.exe x.x.x.x:port" ascii //weight: 1
        $x_1_2 = {6d 61 69 6e 2e 64 66 61 64 66 61 66 64 61 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule VirTool_Win64_Evded_A_2147907237_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Evded.A"
        threat_id = "2147907237"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Evded"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "email.quoprimime" ascii //weight: 1
        $x_1_2 = "evilrdp.gui" ascii //weight: 1
        $x_1_3 = "vchannels" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


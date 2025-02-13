rule HackTool_Win64_ChrmCred_2147798494_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/ChrmCred!MTB"
        threat_id = "2147798494"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ChrmCred"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chromepass Credentials" ascii //weight: 1
        $x_1_2 = "smtp.gmail.com" ascii //weight: 1
        $x_1_3 = "cannot read a text column" ascii //weight: 1
        $x_1_4 = "https://api.ipify.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


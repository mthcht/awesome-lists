rule HackTool_Win64_FileCoder_AMS_2147925765_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/FileCoder.AMS!MTB"
        threat_id = "2147925765"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "The program you are trying to run is malware, that can do real harm to your machine" ascii //weight: 5
        $x_2_2 = "Type \"Yes, I consent.\" to consent." ascii //weight: 2
        $x_1_3 = "Saving consent with time and date" ascii //weight: 1
        $x_1_4 = "As explained, prior to the consent, all program authors are not liable for any damages" ascii //weight: 1
        $x_1_5 = "this program may permanently damage your computer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


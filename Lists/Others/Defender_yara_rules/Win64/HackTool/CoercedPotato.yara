rule HackTool_Win64_CoercedPotato_MX_2147954634_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/CoercedPotato.MX!MTB"
        threat_id = "2147954634"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "CoercedPotato"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CoercedPotato" ascii //weight: 10
        $x_1_2 = "Exploit" ascii //weight: 1
        $x_1_3 = "Prepouce" ascii //weight: 1
        $x_1_4 = "Hack0ura" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule HackTool_Win64_Prolood_A_2147904921_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Prolood.A!MTB"
        threat_id = "2147904921"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Prolood"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "github.com/preludeorg/libraries/go/tests/endpoint" ascii //weight: 1
        $x_1_2 = "Extracting file for quarantine test" ascii //weight: 1
        $x_1_3 = "Pausing for 3 seconds to gauge defensive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


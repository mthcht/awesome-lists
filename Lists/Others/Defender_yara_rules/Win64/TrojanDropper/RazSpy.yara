rule TrojanDropper_Win64_RazSpy_ARA_2147919391_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/RazSpy.ARA!MTB"
        threat_id = "2147919391"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "RazSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/razspy" ascii //weight: 2
        $x_2_2 = "/razrusheniye.exe" ascii //weight: 2
        $x_2_3 = "explorer_injected=success" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


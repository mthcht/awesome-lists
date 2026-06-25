rule HackTool_Win32_Logoloz_2147925474_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Logoloz!MTB"
        threat_id = "2147925474"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Logoloz"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "nicocha30/ligolo-ng/" ascii //weight: 10
        $x_1_2 = "Go build ID:" ascii //weight: 1
        $x_1_3 = "ligolo-ng/cmd/agent" ascii //weight: 1
        $x_1_4 = "protocol/decoder.go" ascii //weight: 1
        $x_1_5 = "maxPayloadSizeForWrite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


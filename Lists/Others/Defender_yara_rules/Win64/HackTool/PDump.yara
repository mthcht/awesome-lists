rule HackTool_Win64_PDump_2147792971_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/PDump!MTB"
        threat_id = "2147792971"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "PDump"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\GLOBAL??\\KnownDlls" ascii //weight: 1
        $x_1_2 = "\\??\\GLOBALROOT" ascii //weight: 1
        $x_1_3 = "EventAggregation.dll" ascii //weight: 1
        $x_1_4 = "SspiCli.dll" ascii //weight: 1
        $x_1_5 = "S-1-5-18" ascii //weight: 1
        $x_1_6 = "S-1-5-19" ascii //weight: 1
        $x_1_7 = "DefineDosDeviceW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


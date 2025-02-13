rule PUA_Win32_MpTestPUAMapKey_266644_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUA:Win32/MpTestPUAMapKey"
        threat_id = "266644"
        type = "PUA"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTestPUAMapKey"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PUA test file MpPUAMapKey" ascii //weight: 1
        $x_1_2 = "Internal test only! Do not distribute outside your team!" ascii //weight: 1
        $x_3_3 = "85721c5d-47cf-452e-8cbb-cd8a324584ca" ascii //weight: 3
        $x_3_4 = "486cebc0-96da-484f-bd8e-1f30b9c2245e" ascii //weight: 3
        $x_3_5 = "f363b1e0-a98d-4f23-8645-e95f59206339" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


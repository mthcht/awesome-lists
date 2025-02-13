rule PUA_Win32_MpTestPUAMapSha1_262058_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUA:Win32/MpTestPUAMapSha1"
        threat_id = "262058"
        type = "PUA"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTestPUAMapSha1"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PUA test file MpPUAMapSha1" ascii //weight: 1
        $x_1_2 = "Internal test only! Do not distribute outside your team!" ascii //weight: 1
        $x_3_3 = "d937a73d-01f4-460f-a450-d93c525f592b" ascii //weight: 3
        $x_3_4 = "486cebc0-96da-484f-bd8e-1f30b9c2245e" ascii //weight: 3
        $x_3_5 = "5a54a627-9913-4ab1-bcf8-981e7d27ac76" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


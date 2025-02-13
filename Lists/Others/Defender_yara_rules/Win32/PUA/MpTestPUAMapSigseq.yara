rule PUA_Win32_MpTestPUAMapSigseq_262059_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUA:Win32/MpTestPUAMapSigseq"
        threat_id = "262059"
        type = "PUA"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTestPUAMapSigseq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PUA test file MpPUAMapSigseq" ascii //weight: 1
        $x_1_2 = "Internal test only! Do not distribute outside your team!" ascii //weight: 1
        $x_3_3 = "d937a73d-01f4-460f-a450-d93c525f592b" ascii //weight: 3
        $x_3_4 = "486cebc0-96da-484f-bd8e-1f30b9c2245e" ascii //weight: 3
        $x_3_5 = "c77c0573-6f30-49d1-a8c9-fe4c6ca96f79" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


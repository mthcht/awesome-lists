rule Ransom_Win64_NefiCrypt_MK_2147759884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/NefiCrypt.MK!MTB"
        threat_id = "2147759884"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "NefiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Go build ID: \"R6dvaUktgv2SjVXDoMdo/kKgwagwoLRC88DpIXAmx/eipNq7_PQCTCOhZ6Q74q/RHJkCaNdTbd6qgYiA-EC\"" ascii //weight: 2
        $x_1_2 = "unreachableuserenv.dll" ascii //weight: 1
        $x_1_3 = "-DECRYPT.txt" ascii //weight: 1
        $x_1_4 = "stoptheworld" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


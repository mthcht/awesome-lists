rule Trojan_DOS_MpTest_A_2147646934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:DOS/MpTest.A"
        threat_id = "2147646934"
        type = "Trojan"
        platform = "DOS: MS-DOS platform"
        family = "MpTest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DOSHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1863618f-a68c-4fcc-90ae-f9603a1d5f5d" ascii //weight: 1
        $x_1_2 = "887815db-1789-4b98-95a1-167a3f1e8452" ascii //weight: 1
        $x_1_3 = "048b9bfd-93f7-46a9-bea1-6500ce503069" ascii //weight: 1
        $x_1_4 = "94e4be85-8d56-428c-a2e8-b202323ac048" ascii //weight: 1
        $x_1_5 = "c7c0c8e2-e02b-400d-a380-93b2f78372e6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


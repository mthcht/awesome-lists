rule Trojan_Linux_MpTest_A_2147646936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MpTest.A"
        threat_id = "2147646936"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MpTest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "21119fb7-763c-400d-b188-ee422a1cec81" ascii //weight: 1
        $x_1_2 = "c01cbb7d-6a5d-4550-b70d-badf377703d4" ascii //weight: 1
        $x_1_3 = "1294c7af-7b8c-46f1-8a8f-12e34e9fd66b" ascii //weight: 1
        $x_1_4 = "17f6765f-4d9e-42b3-8582-d5d64d9b4481" ascii //weight: 1
        $x_1_5 = "6b169586-1364-45aa-81c1-a7568ad21ba8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


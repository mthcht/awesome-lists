rule Trojan_Win32_UacExeTestFile_A_2147691592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UacExeTestFile.A"
        threat_id = "2147691592"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UacExeTestFile"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "8dcf6d1a-65d4-499d-b3c7-be6d416f2cca" ascii //weight: 1
        $x_1_2 = "ce1df18b-8064-4c4d-9a79-9a6ef50bdb51" ascii //weight: 1
        $x_1_3 = "4b85a8e8-dc4d-4219-8074-06f508d20461" ascii //weight: 1
        $x_1_4 = "e5f745b6-b6aa-4a5f-a6e8-31eae3021da0" ascii //weight: 1
        $x_1_5 = "cead6787-45c7-4345-af64-0430f7e82395" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


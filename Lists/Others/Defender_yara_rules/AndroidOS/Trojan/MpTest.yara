rule Trojan_AndroidOS_MpTest_A_2147646932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/MpTest.A"
        threat_id = "2147646932"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "MpTest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2b85aa37-dfec-4d2b-8988-e6f3a10be11e" ascii //weight: 1
        $x_1_2 = "3a7ae70a-cd76-4321-9c08-71ae1f79fde1" ascii //weight: 1
        $x_1_3 = "2fc5df71-8bfe-4b37-9450-ddd00b57d56f" ascii //weight: 1
        $x_1_4 = "7ac1fa7f-058c-46d3-9c2c-676c2157ce33" ascii //weight: 1
        $x_1_5 = "8bfaca24-b5a8-41b8-b7a8-90888db52215" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


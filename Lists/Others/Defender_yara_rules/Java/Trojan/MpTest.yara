rule Trojan_Java_MpTest_A_2147646935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/MpTest.A"
        threat_id = "2147646935"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "MpTest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "62277641-0359-427a-8c7d-299c3668759b" ascii //weight: 1
        $x_1_2 = "a5944828-c699-42e9-bc3a-3a9c7309f947" ascii //weight: 1
        $x_1_3 = "22482fd1-e54c-41e4-b595-c05c13557561" ascii //weight: 1
        $x_1_4 = "37c41da3-5a36-47f8-9c51-ef0c1b3177b0" ascii //weight: 1
        $x_1_5 = "fd5d39f4-b31f-4664-b1ba-11e7b5d7984f" ascii //weight: 1
        $x_1_6 = {b2 12 b6 b2 12 b6 b2 12 b6 b2 12 b6 b2 12 b6 b1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Java_MpTest_B_2147665274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/MpTest.B"
        threat_id = "2147665274"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "MpTest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7cf8f7f6-4a5a-4ac7-8025-ae2e42e3cb32" ascii //weight: 1
        $x_1_2 = "315d0d8f-d758-4b44-a416-2361fd07cd2d" ascii //weight: 1
        $x_1_3 = "01269814-df1a-44ce-9465-1f43b00734e2" ascii //weight: 1
        $x_1_4 = "d31b8b9e-2e9c-4e55-9422-0f6726e3023c" ascii //weight: 1
        $x_1_5 = "361a5b26-a55f-4817-8f19-f27da0fd07c6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


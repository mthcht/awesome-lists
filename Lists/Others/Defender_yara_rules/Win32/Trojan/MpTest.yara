rule Trojan_Win32_MpTest_A_2147683628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTest.A"
        threat_id = "2147683628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4e86e719-5939-4ea8-8f46-c9f15c8ccb0d" ascii //weight: 1
        $x_1_2 = "f2f00bbd-c221-4ffb-b966-ec8742b71d9f" ascii //weight: 1
        $x_1_3 = "0a83d7f3-2371-42dc-b0a1-f1d91be7e58b" ascii //weight: 1
        $x_1_4 = "0c62f35a-33a4-495e-a4fe-998dac3146ab" ascii //weight: 1
        $x_1_5 = "abedda45-5184-4e01-9dd3-8365c469ec43" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


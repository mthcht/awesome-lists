rule Trojan_Win32_FakeAlert_NF_2147905267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAlert.NF!MTB"
        threat_id = "2147905267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAlert"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {a0 38 68 41 00 22 05 12 68 41 00 a2 10 68 41 00 8b 44 24 08 a3 54 68 41 00 2a 05 13 68 41 00 a2 15 68 41 00 0f be 05 11 68 41 00}  //weight: 2, accuracy: High
        $x_1_2 = {ff 75 0c 01 05 50 68 41 00 8b 4d f8 8d 04 1e 6a 03 50 e8 04 fc ff ff 66 c7 05 20 68 41 00 01 00 83 c6 03}  //weight: 1, accuracy: High
        $x_1_3 = "GetCapture" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


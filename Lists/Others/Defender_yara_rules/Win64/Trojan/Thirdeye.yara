rule Trojan_Win64_Thirdeye_A_2147851666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Thirdeye.A"
        threat_id = "2147851666"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Thirdeye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/general/add" ascii //weight: 5
        $x_5_2 = "/ch3ckState" ascii //weight: 5
        $x_5_3 = "B%lHCMQ" ascii //weight: 5
        $x_5_4 = "6cqgli~cy{l" ascii //weight: 5
        $x_5_5 = "#gMVVKIP|N^^G@^" ascii //weight: 5
        $x_5_6 = "3rd_eye" ascii //weight: 5
        $x_5_7 = "USE_DES_KEY_" ascii //weight: 5
        $x_5_8 = {66 c7 45 59 20 00 c7 45 50 20 4d 69 6e c7 45 54 75 74 65 73 c6 45 58 2c}  //weight: 5, accuracy: High
        $x_5_9 = {c7 44 24 54 79 70 65 00 c7 44 24 50 4f 53 5f 74}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


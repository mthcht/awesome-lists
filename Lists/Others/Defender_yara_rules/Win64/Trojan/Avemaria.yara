rule Trojan_Win64_Avemaria_2147951969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Avemaria.MTH!MTB"
        threat_id = "2147951969"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Avemaria"
        severity = "Critical"
        info = "MTH: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {65 48 8b 04 25 30 00 00 00 4c 8b d1 4c 8b 40 60 4d 8b 48 18 49 83 c1 20 49 8b 01 0f 1f 44 00 00 48 39 50 20}  //weight: 2, accuracy: High
        $x_1_2 = "2jkBqQMvH9lvddPWJeYqtC.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


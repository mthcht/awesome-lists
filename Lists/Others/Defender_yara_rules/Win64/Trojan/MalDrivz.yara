rule Trojan_Win64_MalDrivz_A_2147921613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MalDrivz.A!MTB"
        threat_id = "2147921613"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MalDrivz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 0f b7 10 c1 e2 10 41 0f bf 09 81 c2 00 80 00 00 41 03 d3 03 d1 c1 fa 10 66 41 89 10}  //weight: 1, accuracy: High
        $x_1_2 = {41 0f b7 00 c1 e0 10 41 03 c3 c1 f8 10 66 41 89 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 8b 10 8b c2 25 ff ff ff 03 41 8d 0c 83 c1 f9 02 33 ca 81 e1 ff ff ff 03 33 ca 41 89 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


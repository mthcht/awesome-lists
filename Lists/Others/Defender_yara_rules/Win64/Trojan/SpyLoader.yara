rule Trojan_Win64_Spyloader_GPN_2147889099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Spyloader.GPN!MTB"
        threat_id = "2147889099"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Spyloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {31 c0 49 b8 8d 3f 25 1b eb e9 53 0f 48 89 ca 90 48 89 c1 4d 89 c1 83 e1 07 48 c1 e1 03 49 d3 e9 44 30 0c 02 48 83 c0 01 48 83 f8 16 75 e2}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_Tuscas_D_2147794452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tuscas.D!MTB"
        threat_id = "2147794452"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tuscas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8b d0 c1 ea 1c 80 e2 0f 0f b6 ca 8d 41 30 66 83 c1 57 80 fa 39 66 0f 46 c8 41 c1 e0 04 66 41 89 09 4d 8d 49 02 49 ff ca 75}  //weight: 1, accuracy: High
        $x_1_2 = {42 8d 04 12 0f b6 c8 41 8b 00 d3 c8 41 33 c3 2b c2 41 89 00 4d 8d 40 04 ff ca 75 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_Caldera_RTS_2147926538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Caldera.RTS!MTB"
        threat_id = "2147926538"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Caldera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {55 48 89 e5 48 81 ec a8 00 00 00 48 89 84 24 b8 00 00 00 48 89 9c 24 c0 00 00 00 48 ba 23 2e 39 18 55 23 18 4a 48 89 54 24 58 48 ba 57 23 58 62 42 20 0e 05 48 89 54 24 60}  //weight: 2, accuracy: High
        $x_1_2 = "db3411641532182693481445312558207660913467407226562" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


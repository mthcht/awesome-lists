rule Trojan_Win32_Artemis_RDA_2147837022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Artemis.RDA!MTB"
        threat_id = "2147837022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Artemis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 01 00 00 00 d1 e0 0f be 4c 05 d8 c1 e1 06 ba 01 00 00 00 6b c2 03 0f be 54 05 d8 03 ca 8b 45 d0 03 45 dc 88 08 8b 4d dc 83 c1 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


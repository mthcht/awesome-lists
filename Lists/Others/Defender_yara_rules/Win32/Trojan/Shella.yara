rule Trojan_Win32_Shella_GVA_2147946471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shella.GVA!MTB"
        threat_id = "2147946471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shella"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 55 c8 0f be 45 ee 8b 4d b0 33 c8 89 4d b0 8a 55 ef 88 95 40 ff ff ff 80 bd 40 ff ff ff 00 74 1b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


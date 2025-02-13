rule Trojan_Win32_Muzkas_A_2147649352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Muzkas.A"
        threat_id = "2147649352"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Muzkas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 f8 0a 75 1c 68 bc 02 00 00 e8 b9 1b ff ff}  //weight: 2, accuracy: High
        $x_2_2 = {ff 13 50 ff 13 8b f0 8d 55 bc}  //weight: 2, accuracy: High
        $x_2_3 = {ff 51 74 8b 4d fc ba 09 00 00 00 8b 03 8b 30 ff 56 0c 83 7d e4 00 74 61}  //weight: 2, accuracy: High
        $x_1_4 = "ie_guvenlik_plugin" ascii //weight: 1
        $x_1_5 = "security\\.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}


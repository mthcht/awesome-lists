rule TrojanDropper_Win32_Potao_A_2147645579_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Potao.A"
        threat_id = "2147645579"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Potao"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d7 6a 00 bb 80 00 00 00 53 6a 01 6a 00 6a 01 be 00 00 00 c0 56 8d 8d ?? ?? ff ff 51 89 45 ?? ff d0 6a 00 53 6a 01 6a 00 6a 01 89 45 fc 56 8d 85 ?? ?? ff ff 50 ff 55}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8d bd fe fe ff ff 8d b5 fc fe ff ff 89 45 fc 33 d2 2b fb 8b c3 2b f3 8a 08 66 c7 44 07 ff 00 00 80 f9 0d 75 05 88 0c 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


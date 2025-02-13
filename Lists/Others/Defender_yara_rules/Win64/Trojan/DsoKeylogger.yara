rule Trojan_Win64_DsoKeylogger_A_2147888925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DsoKeylogger.A!MTB"
        threat_id = "2147888925"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DsoKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 ff 08 75 0c 4c 8d 05 4a 1f 00 00 e9 a8 01 00 00 83 ff 0d 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


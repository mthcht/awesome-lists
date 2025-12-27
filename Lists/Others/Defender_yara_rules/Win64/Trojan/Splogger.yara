rule Trojan_Win64_Splogger_NK_2147955722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Splogger.NK!MTB"
        threat_id = "2147955722"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Splogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 44 24 28 48 8b 4c 24 20 48 8b 11 48 89 10 48 c7 40 10 06 00 00 00 48 8d 15 c2 44 0c 00 48 89 50 08}  //weight: 2, accuracy: High
        $x_2_2 = {48 89 8c 24 d8 00 00 00 48 89 84 24 e0 00 00 00 48 8d 05 1d a7 0c 00 bb 14 00 00 00 bf 03 00 00 00 48 89 fe 48 8d 8c 24 b8 00 00 00}  //weight: 2, accuracy: High
        $x_1_3 = "KeyLogWriter" ascii //weight: 1
        $x_1_4 = "smr-helper" ascii //weight: 1
        $x_1_5 = "persistentAlloc" ascii //weight: 1
        $x_1_6 = "ImpersonateSelf" ascii //weight: 1
        $x_1_7 = "RevertToSelf" ascii //weight: 1
        $x_1_8 = "hijacked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


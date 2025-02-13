rule TrojanDropper_Win32_Krikun_A_2147609860_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Krikun.A"
        threat_id = "2147609860"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Krikun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "-update" ascii //weight: 10
        $x_10_2 = "SeDebugPrivilege" ascii //weight: 10
        $x_10_3 = "CreateRemoteThread" ascii //weight: 10
        $x_10_4 = "WriteProcessMemory" ascii //weight: 10
        $x_1_5 = {8b 45 08 56 57 8b f1 90 66 3b 46 08 72 ?? 0f b7 f8 8b 06}  //weight: 1, accuracy: Low
        $x_1_6 = {57 50 ff d3 c6 45 e4 2e c6 45 e5 74 90 90}  //weight: 1, accuracy: High
        $x_1_7 = {83 f8 08 77 08 8b 51 18 0f b6 32 eb 19 8b 51 18 83 f8 10 77 05 0f b7 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


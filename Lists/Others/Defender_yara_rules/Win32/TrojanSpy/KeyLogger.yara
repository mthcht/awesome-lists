rule TrojanSpy_Win32_KeyLogger_GC_2147719488_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/KeyLogger.GC!bit"
        threat_id = "2147719488"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b c8 8d 34 10 81 e1 3f 00 00 80 79 05 49 83 c9 c0 41 8a 4c 0c 10 8a 1c 37 32 cb 40 3b c5 88 0e 7c de}  //weight: 2, accuracy: High
        $x_1_2 = "Global\\GLOBAL_SIMICITS_023333_" ascii //weight: 1
        $x_1_3 = {00 5c 69 6e 66 6f 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_4 = "sjiot3016/fkbq(mct" ascii //weight: 1
        $x_1_5 = "Mozilla/4.0 (compatible; MSIE 6.0;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_KeyLogger_HB_2147725641_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/KeyLogger.HB!bit"
        threat_id = "2147725641"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 74 0d dc 6e 41 3b ce 72 f6}  //weight: 1, accuracy: High
        $x_1_2 = {50 6a 00 8d 85 ?? ?? ?? ff 50 8d 85 ?? ?? ?? ff 50 6a 00 56 c7 85 ?? ?? ?? ff 00 00 00 00 ff 15 ?? ?? ?? 00 50 56 ff 15 ?? ?? ?? 00 85 c0 7e 0f 0f be 85 ?? ?? ?? ff 50 68 ?? ?? ?? 00 eb 29 6a 20 8d 45 bc 50 6a 00 56 ff 15 ?? ?? ?? 00 0f b7 c0 c1 e0 10 50 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_2_3 = "IconCache_%02d%02d%02d%02d%02d" ascii //weight: 2
        $x_2_4 = {00 5b 50 61 75 73 65 5d 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_KeyLogger_SP_2147835865_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/KeyLogger.SP!MTB"
        threat_id = "2147835865"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 44 24 1c c7 44 24 18 00 00 00 00 c7 44 24 14 06 00 02 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 28 40 40 00 c7 04 24 01 00 00 80}  //weight: 2, accuracy: High
        $x_1_2 = "\\AppData\\Roaming\\SysMsn.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


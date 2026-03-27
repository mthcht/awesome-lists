rule Trojan_Win64_Splinter_MV_2147853149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Splinter.MV!MSR"
        threat_id = "2147853149"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Splinter"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0hchanLeafinterfacemSpanDeadpanicwaitpclmulqdqpreemptedprofBlockrwxrwxrwxstackpooltracebackwbufSpans0123456789Bad" ascii //weight: 1
        $x_1_2 = "VirtualWSARecvWSASendabortedanalyisanswersavx512fcharsetchunkedconnectconsolecpuprofderivedexpiresflattenfloat32float64forcegcfromstrhttp" ascii //weight: 1
        $x_1_3 = "osxsavepdh.dllprocessrefererrefreshresponereverserunningsandboxserial" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Splinter_MS1_2147961764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Splinter.MS1!dha"
        threat_id = "2147961764"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Splinter"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Implant graceful shutdown" ascii //weight: 10
        $x_10_2 = "struct ImplantId" ascii //weight: 10
        $x_10_3 = "struct ImplantConfig" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Splinter_MS2_2147961765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Splinter.MS2!dha"
        threat_id = "2147961765"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Splinter"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Failed to initialize implant" ascii //weight: 1
        $x_1_2 = "splinter_core\\c2_client\\src\\lib.rs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Splinter_MS3_2147962786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Splinter.MS3!dha"
        threat_id = "2147962786"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Splinter"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Failed to initialize implant" ascii //weight: 10
        $x_10_2 = "implant_exe.pdb" ascii //weight: 10
        $x_5_3 = "loader.dll" ascii //weight: 5
        $x_5_4 = "shellcode" ascii //weight: 5
        $x_5_5 = "UUID parsing failed:" ascii //weight: 5
        $x_5_6 = "Config with" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_5_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Splinter_MS_2147964590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Splinter.MS!dha"
        threat_id = "2147964590"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Splinter"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 57 53 48 81 ec f0 00 00 00 48 89 ce b9 01 02 00 00 48 8d 05 ?? ?? ?? ?? 0f 1f 80 00 00 00 00 80 7c 01 fe 7d 74 ?? 80 7c 01 fd 7d 74 ?? 48 83 f9 03 74 ?? 48 8d 51 fd 80 7c 01 fc 7d 48 89 d1 75}  //weight: 1, accuracy: Low
        $x_1_2 = {7b 22 41 22 3a 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 22 2c 22 42 22 3a 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 22 2c 22 43 22 3a 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 22 2c 22 44 22 3a (74 72|66 61 6c) 2c 22 45 22 3a 22 [0-60] 22 2c 22 46 22 3a [0-15] 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


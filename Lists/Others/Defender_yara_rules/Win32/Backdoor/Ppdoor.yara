rule Backdoor_Win32_Ppdoor_2147602610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ppdoor.gen!dll"
        threat_id = "2147602610"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ppdoor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 08 83 f8 01 74 4d 68 ?? ?? ?? ?? e8 ?? ?? 00 00 83 c4 04 e8 ?? ?? 00 00 b8 01 00 00 00 81 c4 00 02 00 00 c2 0c 00 68 ?? ?? ?? ?? e8 ?? ?? 00 00 83 c4 04 e8 ?? ?? 00 00 b8 01 00 00 00 81 c4 00 02 00 00 c2 0c 00 68 ?? ?? ?? ?? e8 ?? ?? 00 00 83 c4 04 b8 01 00 00 00 81 c4 00 02 00 00 c2 0c 00}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 4c 24 14 8b 54 24 12 8b 44 24 10 81 e1 ff ff 00 00 81 e2 ff ff 00 00 51 25 ff ff 00 00 52 50 8d 4c 24 64 68 ?? ?? ?? ?? 51 ff 15 ?? ?? ?? ?? 8d 54 24 6c 52 56 e8 ?? ?? ff ff 83 c4 1c 57 56 e8 ?? ?? ff ff 83 c4 08 56 ff 15 ?? ?? ?? ?? 5f 5e 81 c4 50 01 00 00 c3}  //weight: 10, accuracy: Low
        $x_10_3 = {51 c7 44 24 3c 44 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 74 39 8b 3d ?? ?? ?? ?? 56 33 f6 8b 54 24 08 52 e8 ?? ?? ff ff 83 c4 04 83 f8 02 75 0a 6a 64 ff d7 46 83 fe 64 7c e4 8b c6 5e 83 e8 64 5f f7 d8 1b c0 24 fe 83 c0 03 83 c4 54 c3 b8 02 00 00 00 5f 83 c4 54 c3}  //weight: 10, accuracy: Low
        $x_2_4 = "c:\\tmp%ld.dat" ascii //weight: 2
        $x_2_5 = "%02d.%02d:%02d" ascii //weight: 2
        $x_2_6 = "[LOAD_" ascii //weight: 2
        $x_2_7 = "DllMain(DLL_PROCESS_DETACH)" ascii //weight: 2
        $x_2_8 = "SRV_LOADER" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_2_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Ppdoor_AV_2147603223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ppdoor.AV"
        threat_id = "2147603223"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ppdoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "82"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "*** PROCESSING UPDATE" ascii //weight: 10
        $x_10_2 = "*** failed to download http data" ascii //weight: 10
        $x_10_3 = "*** Warinig! Zero thread!" ascii //weight: 10
        $x_10_4 = "Available commands:" ascii //weight: 10
        $x_10_5 = "get_drives() received" ascii //weight: 10
        $x_10_6 = "run_file()..." ascii //weight: 10
        $x_10_7 = "SRV_" ascii //weight: 10
        $x_10_8 = {8b c2 83 c4 08 2d e9 03 00 00 0f 84 d7 00 00 00 48 0f 84 9c 00 00 00 48 0f 85 d6 00 00 00 55 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c4 04 33 ed 85 c0 74 65 bf ?? ?? ?? ?? 53 8b 1d ?? ?? ?? ?? 8b f7 8b c5 b9 05 00 00 00 99 f7 f9 85 d2 75 25 81 fe ?? ?? ?? ?? 74 0d 8d 54 24 10 52 e8 ?? ?? ff ff 83 c4 04 8d 44 24 10 68 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b 0f 8d 54 24 10 51 52 ff d3}  //weight: 10, accuracy: Low
        $x_1_9 = "avp32" ascii //weight: 1
        $x_1_10 = "ca.exe" ascii //weight: 1
        $x_1_11 = "pavsrv" ascii //weight: 1
        $x_1_12 = "avguard.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


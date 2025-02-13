rule VirTool_WinNT_Alureon_A_2147724159_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Alureon.A"
        threat_id = "2147724159"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PsSetLoadImageNotifyRoutine" ascii //weight: 1
        $x_1_2 = "KRHT" ascii //weight: 1
        $x_1_3 = "HLLD" ascii //weight: 1
        $x_1_4 = "svchost.exe" wide //weight: 1
        $x_1_5 = "tdlcredo.dll" wide //weight: 1
        $x_1_6 = "tdldns.dll" wide //weight: 1
        $x_10_7 = "\\registry\\machine\\system\\currentcontrolset\\services\\tdlserv" wide //weight: 10
        $x_10_8 = "\\registry\\machine\\system\\currentcontrolset\\control\\safeboot\\minimal\\tdlserv.sys" wide //weight: 10
        $x_10_9 = "\\device\\harddiskvolume%d" wide //weight: 10
        $x_10_10 = {0f a3 0b d6 73 01 ac aa e2 f6}  //weight: 10, accuracy: High
        $x_10_11 = {83 7c 24 04 06 56 75 1e 80 39 0f 75 3a 8d 71 01 8a 16 80 fa 80 72 30 80 fa 8f 77 2b c6 00 0f 8b ce 8a 11 40 eb 13 83 7c 24 08 05 75 1a 8a 11 80 fa e8 74 05 80 fa e9 75 0e}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Alureon_C_2147724167_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Alureon.gen!C"
        threat_id = "2147724167"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Alureon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f2 20 83 b8 ed 89 55 f8 eb 03 d1 6d f8 ff 4d ?? 75 ?? 8b 55 f8 89 94 85 a0 fb ff ff 40 3d 00 01 00 00 7c ?? 83 c8 ff 0f b6 11 ff 4d f4 33 d0 81 e2 ff 00 00 00 c1 e8 08 33 84 95 a0 fb ff ff 41 83 7d f4 00 75 e1 f7 d0 3b 45 ?? 74 08 ff 45 ?? e9 ?? ?? ?? ?? 6a 14 ff 75 ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? 8b 45 14 8b 40 1c 85 c0 74 0f 6a 00 6a 14 8d 4d ?? 51 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


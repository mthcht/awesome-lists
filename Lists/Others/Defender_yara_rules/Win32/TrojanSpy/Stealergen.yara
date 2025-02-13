rule TrojanSpy_Win32_Stealergen_MI_2147808210_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Stealergen.MI!MTB"
        threat_id = "2147808210"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealergen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 3d 74 d1 48 00 00 0f 84 ?? ?? ?? ?? 83 ec 08 0f ae 5c 24 04 8b 44 24 04 25 80 1f 00 00 3d 80 1f 00 00 75 ?? d9 3c 24 66 8b 04 24 66 83 e0 7f 66 83 f8 7f 8d 64 24 08 75 ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = "test4\\e104\\Release\\e104.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


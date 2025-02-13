rule VirTool_WinNT_HideDrv_B_2147599750_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/HideDrv.gen!B"
        threat_id = "2147599750"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "HideDrv"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 00 3d 93 08 00 00 74 ?? 3d 28 0a 00 00 74}  //weight: 1, accuracy: Low
        $x_1_2 = {01 00 fa 0f 20 c0 [0-16] 25 ff ff fe ff [0-16] 0f 22 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {01 00 8b 00 8b 0d ?? ?? 01 00 c7 04 88 ?? ?? 01 00 a1 ?? ?? 01 00 8b 00 8b 0d ?? ?? 01 00 c7 04 88 ?? ?? 01 00 a1 ac [0-96] 0f 22 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {b8 06 00 00 80 eb}  //weight: 1, accuracy: High
        $x_1_5 = "KeServiceDescriptorTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


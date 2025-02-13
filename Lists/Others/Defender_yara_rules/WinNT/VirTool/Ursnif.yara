rule VirTool_WinNT_Ursnif_B_2147618618_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Ursnif.B"
        threat_id = "2147618618"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 0d ?? ?? 14 00 a1 ?? ?? 14 00 8b 40 01 8b 09 8b 35 ?? ?? 14 00 8d 0c 81 ba ?? ?? 14 00 ff d6}  //weight: 2, accuracy: Low
        $x_2_2 = {c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 eb 5c 39 0d ?? ?? 14 00 75 54 68 57 64 6d 20 57 6a 01}  //weight: 2, accuracy: Low
        $x_1_3 = "\\hide_evr2.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Ursnif_C_2147622349_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Ursnif.C"
        threat_id = "2147622349"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 06 8d 04 3e 50 68 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 83 c4 0c 85 c0 75 06 89 35 ?? ?? ?? 00 46 81 fe 00 30 00 00 7c d9}  //weight: 1, accuracy: Low
        $x_1_2 = "InterlockedExchange" ascii //weight: 1
        $x_1_3 = "ZwEnumerateValueKey" ascii //weight: 1
        $x_1_4 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_5 = "ZwQueryDirectoryFile" ascii //weight: 1
        $x_1_6 = "ZwQuerySystemInformation" ascii //weight: 1
        $x_1_7 = "hide_evr2.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


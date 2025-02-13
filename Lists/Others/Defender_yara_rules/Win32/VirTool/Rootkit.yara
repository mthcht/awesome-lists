rule VirTool_Win32_Rootkit_BW_2147636735_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Rootkit.BW"
        threat_id = "2147636735"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Rootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 0c 50 83 f1 ?? 8b 55 ?? 8b 45 10 66 89 0c 50 eb d6}  //weight: 2, accuracy: Low
        $x_1_2 = {0f b7 51 06 83 ea 01 6b d2 28}  //weight: 1, accuracy: High
        $x_2_3 = "\\i386\\hcpidesk.pdb" ascii //weight: 2
        $x_1_4 = "BaseNamedObjects\\UID_1329147602_MIE" ascii //weight: 1
        $x_1_5 = "mRoot\\system32\\kernel32.dl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


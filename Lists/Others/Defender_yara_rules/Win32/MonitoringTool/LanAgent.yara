rule MonitoringTool_Win32_LanAgent_145153_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/LanAgent"
        threat_id = "145153"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "LanAgent"
        severity = "7"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6b 65 79 2e 64 61 74 00 ff ff ff ff 0f 00 00 00 73 63 72 65 65 6e 73 68 6f 74 73 2e 64 61 74 00 [0-8] ff ff ff ff 07 00 00 00 61 70 70 2e 64 61 74 00 ff ff ff ff 0d 00 00 00 63 6c 69 70 62 6f 61 72 64 2e 64 61 74 00 00 00 ff ff ff ff 08 00 00 00 70 72 6e 74 2e 64 61 74}  //weight: 10, accuracy: Low
        $x_1_2 = "Global\\SettingsFileMap" ascii //weight: 1
        $x_1_3 = "Global\\InfoFileMapApp" ascii //weight: 1
        $x_1_4 = "Global\\InfoFIleMapSrv" ascii //weight: 1
        $x_1_5 = "Global\\ActActionUnInst" ascii //weight: 1
        $x_1_6 = "Global\\ActActionDrive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


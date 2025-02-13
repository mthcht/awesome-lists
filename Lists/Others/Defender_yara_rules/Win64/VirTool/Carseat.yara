rule VirTool_Win64_Carseat_A_2147927349_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Carseat.A"
        threat_id = "2147927349"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Carseat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "commands\\windowsautologon_command.py" ascii //weight: 1
        $x_1_2 = "\\scheduledtasks_command.py" ascii //weight: 1
        $x_1_3 = "rdpsavedconnections_command.py" ascii //weight: 1
        $x_1_4 = "processcreationevents_command.py" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


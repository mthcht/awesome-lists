rule Backdoor_Win64_FreshCam_A_2147925347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/FreshCam.A!dha"
        threat_id = "2147925347"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "FreshCam"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "src\\commands\\send_cmd.rs " ascii //weight: 1
        $x_1_2 = "src\\commands\\send_status.rs" ascii //weight: 1
        $x_1_3 = "src\\commands\\upload_data.rs" ascii //weight: 1
        $x_1_4 = "src\\commands\\download_data.rs" ascii //weight: 1
        $x_1_5 = "src\\commands\\technical_command.rs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_FreshCam_B_2147925348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/FreshCam.B!dha"
        threat_id = "2147925348"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "FreshCam"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "src\\commands\\send_ok.rs" ascii //weight: 1
        $x_1_2 = "src\\commands\\get_data.rs" ascii //weight: 1
        $x_1_3 = "src\\commands\\do_command.rs" ascii //weight: 1
        $x_1_4 = "src\\commands\\send_data.rs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


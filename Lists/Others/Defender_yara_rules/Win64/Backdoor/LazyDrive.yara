rule Backdoor_Win64_LazyDrive_A_2147961009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/LazyDrive.A!dha"
        threat_id = "2147961009"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "LazyDrive"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "normal-sleepy" ascii //weight: 1
        $x_1_2 = "semi-sleepy" ascii //weight: 1
        $x_1_3 = "Sleepy status" ascii //weight: 1
        $x_2_4 = "Error in getting value from json file , maybe Cgrid is invalid" ascii //weight: 2
        $x_2_5 = "/v1.0/me/drive/root:/employee/Folder_Name/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


rule Backdoor_Win32_Shesmi_A_2147705985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Shesmi.A"
        threat_id = "2147705985"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Shesmi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "sheshzmy" ascii //weight: 5
        $x_5_2 = "20cnFTP" ascii //weight: 5
        $x_1_3 = {00 32 33 30 20}  //weight: 1, accuracy: High
        $x_1_4 = {00 33 33 31 20}  //weight: 1, accuracy: High
        $x_1_5 = {00 32 30 30 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


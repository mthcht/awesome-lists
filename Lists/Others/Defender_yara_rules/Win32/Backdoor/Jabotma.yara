rule Backdoor_Win32_Jabotma_A_2147721772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Jabotma.A"
        threat_id = "2147721772"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Jabotma"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "_vbs_jama" ascii //weight: 1
        $x_1_2 = "DoExec2" ascii //weight: 1
        $x_1_3 = "- --- sent: --- -" ascii //weight: 1
        $x_1_4 = {2f 62 6f 74 6e 65 74 7a 3f 61 3d [0-10] 26 67 75 69 64 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


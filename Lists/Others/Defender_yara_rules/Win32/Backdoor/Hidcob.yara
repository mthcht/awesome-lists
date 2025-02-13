rule Backdoor_Win32_Hidcob_A_2147725898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hidcob.A"
        threat_id = "2147725898"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hidcob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ghfghjuyufgdgftr" ascii //weight: 1
        $x_1_2 = "q45tyu6hgvhi7^%$sdf" ascii //weight: 1
        $x_1_3 = "m*^&^ghfge4wer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


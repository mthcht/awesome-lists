rule Backdoor_Win32_Tweramod_A_2147661532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tweramod.A"
        threat_id = "2147661532"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tweramod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell Exit!" ascii //weight: 1
        $x_1_2 = "Unable to Traverse Folder!" ascii //weight: 1
        $x_1_3 = "Service stoped" ascii //weight: 1
        $x_1_4 = "Hello,Hell!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


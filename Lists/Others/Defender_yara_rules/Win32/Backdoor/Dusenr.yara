rule Backdoor_Win32_Dusenr_A_2147688619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dusenr.A"
        threat_id = "2147688619"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dusenr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "Shell.Dusn" ascii //weight: 5
        $x_5_2 = "Global\\WINPOPUP_MEMORY" ascii //weight: 5
        $x_5_3 = {63 66 67 3a [0-32] 2e 74 6d 70}  //weight: 5, accuracy: Low
        $x_5_4 = "ext\\settings\\{11f09afe-75ad-4e52-ab43-e09e9351ce17}" wide //weight: 5
        $x_5_5 = "cnrdn.com" ascii //weight: 5
        $x_5_6 = ".cnzz.com/stat.php?id" ascii //weight: 5
        $x_2_7 = "Server: Apache" ascii //weight: 2
        $x_2_8 = "208.67." ascii //weight: 2
        $x_2_9 = "114.114." ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}


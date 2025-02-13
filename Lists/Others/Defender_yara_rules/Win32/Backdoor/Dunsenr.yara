rule Backdoor_Win32_Dunsenr_B_2147689270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dunsenr.B"
        threat_id = "2147689270"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dunsenr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Global\\WINPOPUP_MEMORY" ascii //weight: 1
        $x_1_2 = {63 66 67 3a [0-32] 2e 74 6d 70}  //weight: 1, accuracy: Low
        $x_1_3 = "ext\\settings\\{11f09afe-75ad-4e52-ab43-e09e9351ce17}" wide //weight: 1
        $x_1_4 = ".cnzz.com/stat.php?id" ascii //weight: 1
        $x_1_5 = {75 6e 61 6d 65 3d 00 00 2f 64 6f 77 61 6e 72 65 67 6e 65 77}  //weight: 1, accuracy: High
        $x_1_6 = "118.192.91.35" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


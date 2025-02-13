rule Backdoor_Win32_ATMRippery_A_2147717125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/ATMRippery.A"
        threat_id = "2147717125"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "ATMRippery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "taskkill /IM dbackup.exe" ascii //weight: 1
        $x_1_2 = "\\System32\\dbackup.exe" ascii //weight: 1
        $x_1_3 = "DBackup Service" wide //weight: 1
        $x_10_4 = "ATMRipper" ascii //weight: 10
        $x_10_5 = {50 33 db 68 98 01 00 00 43 51 89}  //weight: 10, accuracy: High
        $x_1_6 = {44 69 73 70 65 6e 73 69 6e 67 [0-32] 63 61 73 68}  //weight: 1, accuracy: Low
        $x_1_7 = "3.HIDE" ascii //weight: 1
        $x_1_8 = "2.CLEAN LOGS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}


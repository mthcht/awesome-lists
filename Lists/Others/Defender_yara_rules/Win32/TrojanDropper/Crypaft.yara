rule TrojanDropper_Win32_Crypaft_2147608149_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Crypaft"
        threat_id = "2147608149"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Crypaft"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2" wide //weight: 1
        $x_1_2 = "Select * from Win32_BaseBoard" wide //weight: 1
        $x_1_3 = "[Raft]" wide //weight: 1
        $x_1_4 = "Sandboxie detected!" wide //weight: 1
        $x_1_5 = "Sandboxie not detected!" wide //weight: 1
        $x_1_6 = "File is sandboxed!" wide //weight: 1
        $x_1_7 = "SYNTHETICUSER.FGVS" wide //weight: 1
        $x_1_8 = "Services.exe" wide //weight: 1
        $x_5_9 = {43 72 79 70 74 6f 53 74 75 62 00}  //weight: 5, accuracy: High
        $x_5_10 = {43 72 79 70 74 6f 2d 53 74 75 62 00 43 72 79 70 74 2d 6f 2d 52 61 66 74 00}  //weight: 5, accuracy: High
        $x_5_11 = {43 72 79 70 74 6f 52 43 34 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 6 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


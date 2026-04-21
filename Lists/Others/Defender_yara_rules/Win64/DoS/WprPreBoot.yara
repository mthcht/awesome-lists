rule DoS_Win64_WprPreBoot_A_2147967369_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win64/WprPreBoot.A!dha"
        threat_id = "2147967369"
        type = "DoS"
        platform = "Win64: Windows 64-bit platform"
        family = "WprPreBoot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fatal: Failed to open registry key. Please run this program as an Administrator." ascii //weight: 1
        $x_1_2 = "file(s) and the program itself to PendingFileRenameOperations." ascii //weight: 1
        $x_2_3 = "\\WindowsRedTeaming\\Learn\\Wiper\\" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}


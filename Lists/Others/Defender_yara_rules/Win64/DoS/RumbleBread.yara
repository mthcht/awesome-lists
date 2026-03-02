rule DoS_Win64_RumbleBread_A_2147963985_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win64/RumbleBread.A!dha"
        threat_id = "2147963985"
        type = "DoS"
        platform = "Win64: Windows 64-bit platform"
        family = "RumbleBread"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\PhysicalDrive0" ascii //weight: 1
        $x_1_2 = "C:\\\\Windows|C:\\\\Users|C:\\\\ProgramData" ascii //weight: 1
        $x_1_3 = "Symantec|Windows Defender|ESET|microsoft shared|Windows NT|AppData|Microsoft\\\\WindowsApps|desktop.ini" ascii //weight: 1
        $x_2_4 = "/Windows/twain_32.bat" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


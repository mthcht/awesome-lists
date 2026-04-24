rule DoS_Win32_EchoWiper_A_2147967739_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/EchoWiper.A!dha"
        threat_id = "2147967739"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "EchoWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FPC 3.2.2 [2025/11/08] for i386 - Win32" ascii //weight: 1
        $x_1_2 = "listallfilesinnesteddirectories" ascii //weight: 1
        $x_1_3 = "\\\\.\\PhysicalDrive%d" ascii //weight: 1
        $x_1_4 = "TFileRewriteThread" ascii //weight: 1
        $x_1_5 = "TFilesArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


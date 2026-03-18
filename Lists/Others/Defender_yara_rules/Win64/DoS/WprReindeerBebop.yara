rule DoS_Win64_WprReindeerBebop_C_2147965057_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win64/WprReindeerBebop.C!dha"
        threat_id = "2147965057"
        type = "DoS"
        platform = "Win64: Windows 64-bit platform"
        family = "WprReindeerBebop"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Failed to open disk. Error:" ascii //weight: 1
        $x_1_2 = "IOCTL failed. Error:" ascii //weight: 1
        $x_1_3 = "Drive layout deleted successfully." ascii //weight: 1
        $x_1_4 = "\\\\.\\PhysicalDrive%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


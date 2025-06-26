rule DoS_Win32_GigaWiper_B_2147944724_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/GigaWiper.B!dha"
        threat_id = "2147944724"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "GigaWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Pass Time took: %s" ascii //weight: 1
        $x_1_2 = "Failed to open drive %s: %v" ascii //weight: 1
        $x_1_3 = "Bytes to disk. counter:" ascii //weight: 1
        $x_1_4 = "Pass %d complete(Random)." ascii //weight: 1
        $x_1_5 = "Error during write: %v" ascii //weight: 1
        $x_1_6 = "Failed to get disk size: %v" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


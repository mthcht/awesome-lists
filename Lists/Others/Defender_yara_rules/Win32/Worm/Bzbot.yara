rule Worm_Win32_Bzbot_C_2147626910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bzbot.C"
        threat_id = "2147626910"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bzbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "simple string to avoid stupid av detections" ascii //weight: 1
        $x_1_2 = "I am a nigger" ascii //weight: 1
        $x_1_3 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_4 = "GetFileSize" ascii //weight: 1
        $x_1_5 = "sandbox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


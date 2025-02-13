rule Worm_Win32_Frethog_AI_2147639629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Frethog.AI!dll"
        threat_id = "2147639629"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UPDATEDATA:" ascii //weight: 1
        $x_1_2 = "DOWNLOAD:" ascii //weight: 1
        $x_2_3 = "VERSON:Ant-V" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


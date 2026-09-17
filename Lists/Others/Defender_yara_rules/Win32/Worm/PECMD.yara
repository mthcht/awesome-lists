rule Worm_Win32_PECMD_YAE_2147978366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/PECMD.YAE!MTB"
        threat_id = "2147978366"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "PECMD"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PECMD.exe" ascii //weight: 1
        $x_1_2 = "System Volume Information" ascii //weight: 1
        $x_1_3 = "file %myname%=>%temp%\\spri.exe" ascii //weight: 1
        $x_1_4 = "find System Idle Process,! team exec %temp%\\spri.exe LOAD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


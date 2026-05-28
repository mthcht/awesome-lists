rule Trojan_Win32_BlueWipe_GA_2147970406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlueWipe.GA!MTB"
        threat_id = "2147970406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlueWipe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "E:\\files\\new\\GRAT\\CWipe\\Release\\CWipe.pdb" ascii //weight: 10
        $x_1_2 = "--- Working on" ascii //weight: 1
        $x_1_3 = "\\\\.\\PhysicalDrive" ascii //weight: 1
        $x_1_4 = "Partitions removed successfully." ascii //weight: 1
        $x_1_5 = "Pass Time took:" ascii //weight: 1
        $x_1_6 = "Buffer size:" ascii //weight: 1
        $x_1_7 = "Drive size:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


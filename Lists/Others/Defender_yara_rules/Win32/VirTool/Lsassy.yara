rule VirTool_Win32_Lsassy_A_2147797320_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Lsassy.A!MTB"
        threat_id = "2147797320"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Lsassy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lsassy.exec.wmi" ascii //weight: 1
        $x_1_2 = "lsassy.dumper" ascii //weight: 1
        $x_1_3 = "lsassy.credential" ascii //weight: 1
        $x_1_4 = "dumpmethod.dumpert" ascii //weight: 1
        $x_1_5 = "dumpmethod.dllinject" ascii //weight: 1
        $x_1_6 = "minidump.streams" ascii //weight: 1
        $x_1_7 = "minikerberos.common" ascii //weight: 1
        $x_1_8 = "pypykatz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


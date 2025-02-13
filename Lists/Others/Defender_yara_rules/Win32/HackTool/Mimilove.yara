rule HackTool_Win32_Mimilove_A_2147770264_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mimilove.A!dha"
        threat_id = "2147770264"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mimilove"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LSASRV Credentials (MSV1_0, ...)" wide //weight: 1
        $x_1_2 = "KERBEROS Credentials (no tickets, sorry)" wide //weight: 1
        $x_1_3 = "mimilove_kerberos" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


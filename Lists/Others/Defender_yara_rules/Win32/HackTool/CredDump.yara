rule HackTool_Win32_CredDump_A_2147741713_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CredDump.A"
        threat_id = "2147741713"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CredDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\cred.txt" ascii //weight: 1
        $x_1_2 = "\\creddump.dll" ascii //weight: 1
        $x_1_3 = "Credential Set: Enterprise" ascii //weight: 1
        $x_1_4 = "%s\\Microsoft\\Credentials\\%s\\credentials" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


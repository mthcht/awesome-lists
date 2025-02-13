rule HackTool_Win32_PWDump_2147741322_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PWDump"
        threat_id = "2147741322"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PWDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "PwDump" ascii //weight: 5
        $x_1_2 = "\\SAM\\Domains\\Account" ascii //weight: 1
        $x_1_3 = "\\Control\\Lsa\\" ascii //weight: 1
        $x_1_4 = "RegQueryValueExW" ascii //weight: 1
        $x_1_5 = "CryptCreateHash" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_PWDump_I_2147741330_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PWDump.I"
        threat_id = "2147741330"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PWDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "raw password extractor" ascii //weight: 1
        $x_1_2 = "system passwords" ascii //weight: 1
        $x_1_3 = "passwords from files" ascii //weight: 1
        $x_1_4 = "savedump.dat" ascii //weight: 1
        $x_1_5 = "reading hive root key" ascii //weight: 1
        $x_1_6 = "SAM\\Domains\\Account" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


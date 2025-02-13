rule Trojan_Win32_FormatC_I_2147611254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FormatC.I"
        threat_id = "2147611254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FormatC"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WARNING, ALL DATA ON NON-REMOVABLE DISK" ascii //weight: 1
        $x_1_2 = "C:\\WINDOWS>format c:" ascii //weight: 1
        $x_1_3 = "C:\\WINDOWS\\system32\\cmd.exe /c dir/s c:\\*.*>>format~.tmp" ascii //weight: 1
        $x_1_4 = "Microsoft(R) Windows 98" ascii //weight: 1
        $x_1_5 = "Borland C++ - Copyright 1996" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Backdoor_Win32_Buterat_C_2147720684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Buterat.C!bit"
        threat_id = "2147720684"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Buterat"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "liuliangbao" wide //weight: 1
        $x_1_2 = "SCConfig.dat" wide //weight: 1
        $x_1_3 = "CFGUpdate" wide //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


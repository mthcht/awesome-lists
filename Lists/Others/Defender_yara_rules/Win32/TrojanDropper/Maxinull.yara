rule TrojanDropper_Win32_Maxinull_C_2147814866_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Maxinull.C!dha"
        threat_id = "2147814866"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Maxinull"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DsfbufQspdfttB" ascii //weight: 1
        $x_1_2 = "XiS92BfOXoyRp5V6932M" ascii //weight: 1
        $x_1_3 = "dne/fyf" ascii //weight: 1
        $x_1_4 = "<!-- i -->" ascii //weight: 1
        $x_1_5 = "image/x-xbitmap" wide //weight: 1
        $x_1_6 = "ProxyOverride" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}


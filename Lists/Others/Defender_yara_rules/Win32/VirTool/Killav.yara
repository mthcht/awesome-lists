rule VirTool_Win32_Killav_2147582345_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Killav"
        threat_id = "2147582345"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AntiKaspersky " ascii //weight: 1
        $x_1_2 = "Build: " ascii //weight: 1
        $x_1_3 = "kas2k, toolz.pyccxak.com" ascii //weight: 1
        $x_1_4 = "Error N1!, CommandLine NULL." ascii //weight: 1
        $x_1_5 = "File Crypted!" ascii //weight: 1
        $x_1_6 = "FUCK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


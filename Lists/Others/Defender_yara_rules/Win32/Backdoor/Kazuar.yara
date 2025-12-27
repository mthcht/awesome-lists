rule Backdoor_Win32_Kazuar_I_2147946886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kazuar.I!dha"
        threat_id = "2147946886"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kazuar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$payload_filename" wide //weight: 1
        $x_1_2 = "%ls\\%ls" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


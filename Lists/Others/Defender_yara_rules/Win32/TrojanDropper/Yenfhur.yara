rule TrojanDropper_Win32_Yenfhur_A_2147639530_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Yenfhur.A"
        threat_id = "2147639530"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Yenfhur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kuser.dll+mukmil.dll+vumer.dll" wide //weight: 1
        $x_1_2 = "ressigname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


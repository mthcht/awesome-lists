rule Ransom_Win32_GermanWiper_SA_2147741692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GermanWiper.SA!dha"
        threat_id = "2147741692"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GermanWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IP_DEST_PORT_UNREACHABLE (11005)" ascii //weight: 1
        $x_1_2 = "nine.exe" ascii //weight: 1
        $x_1_3 = "Friction Tweeter Casting" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


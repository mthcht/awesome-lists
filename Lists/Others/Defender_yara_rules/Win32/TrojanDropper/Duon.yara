rule TrojanDropper_Win32_Duon_2147599592_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Duon"
        threat_id = "2147599592"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Duon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "[UnDo_Crypt]" wide //weight: 5
        $x_1_2 = "[21space]" wide //weight: 1
        $x_1_3 = "[23space]" wide //weight: 1
        $x_1_4 = "[10space]" wide //weight: 1
        $x_1_5 = "[19space]" wide //weight: 1
        $x_1_6 = "[18space]" wide //weight: 1
        $x_5_7 = "-C000-decrypter" ascii //weight: 5
        $x_5_8 = "modSpaceRemove" ascii //weight: 5
        $x_5_9 = "MainMOD" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}


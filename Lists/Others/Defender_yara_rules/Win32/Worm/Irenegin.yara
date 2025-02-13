rule Worm_Win32_Irenegin_A_2147615825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Irenegin.A"
        threat_id = "2147615825"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Irenegin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "attrib +h autorun.inf" ascii //weight: 10
        $x_10_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 3d [0-8] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_5_3 = "NetShareAdd" ascii //weight: 5
        $x_5_4 = "GetDriveTypeA" ascii //weight: 5
        $x_1_5 = "Fiestas" ascii //weight: 1
        $x_1_6 = "[AutoRun]" ascii //weight: 1
        $x_1_7 = "MediaPath" ascii //weight: 1
        $x_1_8 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


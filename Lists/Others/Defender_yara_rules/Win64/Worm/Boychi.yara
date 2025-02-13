rule Worm_Win64_Boychi_A_2147661345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win64/Boychi.A!sys"
        threat_id = "2147661345"
        type = "Worm"
        platform = "Win64: Windows 64-bit platform"
        family = "Boychi"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\DosDevices\\MSH4DEV1" wide //weight: 1
        $x_2_2 = {40 53 48 83 ec 30 ba 40 00 00 00 33 c9 41 b8 44 52 4d 4d}  //weight: 2, accuracy: High
        $x_2_3 = {66 f2 af 49 8b d0 48 f7 d1 48 ff c9 0f b7 c1 66 03 c0 66 89 44 24 30}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


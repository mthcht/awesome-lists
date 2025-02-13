rule Worm_Win32_Picsys_BQ_2147889104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Picsys.BQ!MTB"
        threat_id = "2147889104"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Picsys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 7b e1 b0 e7 1b 4f 03 56 aa 32 66 09 ba af 6d 0b 74 17 66 7d c0 c5 50 36 80 6d c3 2f c1 c8 58 81 f1 5e ff e1 5e 1a 61 f0 3b 4a fc 42 8b 52 e1}  //weight: 1, accuracy: High
        $x_1_2 = {71 f9 3f 83 e7 bf 6f f1 e8 02 72 36 c1 eb 52 3d 96 29 11 74 3d 2d 93 df be df b6 2e 22 13 02 24 eb 3a 2d fd 0e 2f 27 3d 74 26 eb 75 ff 0b fd 2c b0 c8 eb 2a b0}  //weight: 1, accuracy: High
        $x_1_3 = {08 b9 0c 33 c1 9f 53 4c ff d1 8a 37 ff 64 a3 42 7f a0 d8 2c a8 5a 54 55 57 1d 4a c1 c7 56 53 41 07 7b 6c ad 90 8b}  //weight: 1, accuracy: High
        $x_1_4 = {55 50 58 31 00 61 23 a4 00 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Picsys_ASC_2147898606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Picsys.ASC!MTB"
        threat_id = "2147898606"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Picsys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fistfucking and how ide it goes.mpg.pif" ascii //weight: 1
        $x_1_2 = "nymph enjoys fisting all the way to the elbow.mpg.pif" ascii //weight: 1
        $x_1_3 = "blonde babe handfucking herself.mpg.pif" ascii //weight: 1
        $x_1_4 = "sexy bi guys doing a chick together.mpg.pif" ascii //weight: 1
        $x_1_5 = "blonde sucking and fucks outdoor.mpg.pif" ascii //weight: 1
        $x_1_6 = "sexy fucked tranny babe.mpg.pif" ascii //weight: 1
        $x_1_7 = "beautiful babes extending love and compassion.mpg.pif" ascii //weight: 1
        $x_1_8 = "teen hottie geting buttfucked.mpg.pif" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


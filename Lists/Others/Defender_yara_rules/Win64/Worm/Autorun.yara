rule Worm_Win64_Autorun_KK_2147968516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win64/Autorun.KK!MTB"
        threat_id = "2147968516"
        type = "Worm"
        platform = "Win64: Windows 64-bit platform"
        family = "Autorun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "open=allow.exe" ascii //weight: 5
        $x_4_2 = "C:\\Program Files\\KaZaa\\" ascii //weight: 4
        $x_3_3 = "Software\\Kazaa\\Transfer" ascii //weight: 3
        $x_2_4 = "Hunatcha Informer" ascii //weight: 2
        $x_1_5 = "Your system need to update my new world..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


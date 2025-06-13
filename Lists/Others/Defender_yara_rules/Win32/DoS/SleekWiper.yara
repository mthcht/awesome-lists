rule DoS_Win32_SleekWiper_A_2147943066_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/SleekWiper.A!dha"
        threat_id = "2147943066"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "SleekWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Domestos.exe" ascii //weight: 1
        $x_1_2 = "VGAuthService.exe" ascii //weight: 1
        $x_1_3 = "vm3dservice.exe" ascii //weight: 1
        $x_1_4 = "[System Process]" ascii //weight: 1
        $x_1_5 = "*.onetoc2" ascii //weight: 1
        $x_1_6 = "*.PAQ" ascii //weight: 1
        $x_10_7 = {81 f9 4d 53 44 4f 75 ?? 3d 53 35 2e 30}  //weight: 10, accuracy: Low
        $x_10_8 = {81 f9 4e 54 46 53 75 ?? 3d 20 20 20 20}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}


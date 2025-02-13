rule Backdoor_Win32_ShadowHammer_A_2147734416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/ShadowHammer.A!dha"
        threat_id = "2147734416"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "ShadowHammer"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 40 68 00 10 00 00 68 00 ?? ?? 00 6a 00 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {ad ab e2 fc 58 05 ?? ?? 00 00 ff d0}  //weight: 10, accuracy: Low
        $x_10_3 = "ASUSTeK Computer Inc.1" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_ShadowHammer_ShadowHammer_2147734427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/ShadowHammer!!ShadowHammer.C!dha"
        threat_id = "2147734427"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "ShadowHammer"
        severity = "Critical"
        info = "C: an internal category used to refer to some threats"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {da b6 ac e6 c7 [0-5] c2 5c 37 99}  //weight: 10, accuracy: Low
        $x_10_2 = {59 77 ba a3 c7 [0-5] f8 ce 0c a1}  //weight: 10, accuracy: Low
        $x_10_3 = {ad e6 2a 25 c7 [0-5] 7a df 11 84}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_ShadowHammer_C_2147734444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/ShadowHammer.C!dha"
        threat_id = "2147734444"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "ShadowHammer"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "D:\\C++\\AsusShellCode\\Release\\AsusShellCode.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


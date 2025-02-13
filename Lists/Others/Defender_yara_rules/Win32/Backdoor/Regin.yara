rule Backdoor_Win32_Regin_F_2147691717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Regin.F!dha"
        threat_id = "2147691717"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Regin"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 00 01 00 b9 b2 00 00 00 33 c0}  //weight: 1, accuracy: High
        $x_1_2 = {80 3c 1e 2e 74 18 8b fb 83 c9 ff 33 c0 46 f2 ae}  //weight: 1, accuracy: High
        $x_1_3 = {6a 21 50 e8 ?? ?? ?? ?? 83 c4 08 [0-32] 6a 21 56 e8}  //weight: 1, accuracy: Low
        $x_1_4 = "{66fbe87a-4372-1f51-101d-1aaf0043127a}" ascii //weight: 1
        $x_1_5 = "{44fdg23a-1522-6f9e-d05d-1aaf0176138a}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Regin_G_2147691718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Regin.G!dha"
        threat_id = "2147691718"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Regin"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d f4 01 00 00 75 07 68 ?? ?? ?? ?? eb 21 3d 58 02 00 00 75 07 68 ?? ?? ?? ?? eb 13 3d bc 02 00 00 75 07 68 ?? ?? ?? ?? eb 05}  //weight: 1, accuracy: Low
        $x_1_2 = {3c 20 7c 04 3c 7f 7c 08 3c 09}  //weight: 1, accuracy: High
        $x_1_3 = {00 70 77 20 63 68 61 6e 67 65 64 3a 00}  //weight: 1, accuracy: High
        $x_1_4 = " filespec|!sys!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


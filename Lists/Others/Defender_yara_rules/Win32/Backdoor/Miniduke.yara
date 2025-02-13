rule Backdoor_Win32_Miniduke_C_2147705735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Miniduke.C!dha"
        threat_id = "2147705735"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Miniduke"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encryptedusername" ascii //weight: 1
        $x_1_2 = "encryptedpassword" ascii //weight: 1
        $x_1_3 = "from moz_logins" ascii //weight: 1
        $x_2_4 = "\\bin\\bot.pdb" ascii //weight: 2
        $x_2_5 = "\\NITRO\\SVA\\Generations\\" ascii //weight: 2
        $x_2_6 = "INTERNET EXPLORER 7.x-8.x HTTPPASS" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}


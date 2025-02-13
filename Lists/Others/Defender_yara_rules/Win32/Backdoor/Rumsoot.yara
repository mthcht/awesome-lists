rule Backdoor_Win32_Rumsoot_A_2147605610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rumsoot.A"
        threat_id = "2147605610"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rumsoot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {59 3d 80 51 01 00 7c 05 e8 ?? ?? ff ff e8 ?? ?? ff ff 68 c0 27 09 00 ff 15 ?? ?? 00 01 eb (c9|ce)}  //weight: 2, accuracy: Low
        $x_1_2 = "uid=%I64d&gid=%d&cid=%s&rid=%d&sid=%d" ascii //weight: 1
        $x_1_3 = "runassysuser" ascii //weight: 1
        $x_1_4 = "will result in system instability" ascii //weight: 1
        $x_1_5 = "\\projects\\cvs_port\\port\\tools\\loader_our\\Bin\\i386\\a_loader.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


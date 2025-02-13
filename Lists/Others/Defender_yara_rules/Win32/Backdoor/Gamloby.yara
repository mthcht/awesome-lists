rule Backdoor_Win32_Gamloby_A_2147718522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Gamloby.A!bit"
        threat_id = "2147718522"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamloby"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "C:\\$MSRecycle.Bin\\MicroRecycle.dll" ascii //weight: 10
        $x_10_2 = "C:\\$MSRecycle.Bin\\TsiService.exe" ascii //weight: 10
        $x_10_3 = "C:\\$MSRecycle.Bin\\xp.ios" ascii //weight: 10
        $x_1_4 = "\\RemoteDll\\release\\RemoteDll.pdb" ascii //weight: 1
        $x_1_5 = "sc config %s start= auto" ascii //weight: 1
        $x_1_6 = {8a 1c 06 88 1c 01 88 14 06 0f b6 1c 01 0f b6 d2 03 da 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 0f b6 14 03 30 14 2f 83 c7 01 3b 7c 24 1c 72}  //weight: 1, accuracy: High
        $x_1_7 = {68 02 20 00 00 68 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 6a 00 68 ?? ?? ?? 00 6a 00 8d 84 24 ?? ?? 00 00 50 68 ?? ?? ?? 00 6a 00 ff 15 ?? ?? ?? 00 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


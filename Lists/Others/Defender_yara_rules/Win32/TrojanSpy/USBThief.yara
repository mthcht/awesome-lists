rule TrojanSpy_Win32_USBThief_A_2147722519_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/USBThief.A!bit"
        threat_id = "2147722519"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "USBThief"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b f0 85 f6 74 2a 8b 4d 08 53 51 ff 15 ?? ?? ?? ?? 03 c6 83 e7 0f 76 14 8d 9b 00 00 00 00 3b f0 73 0e 4f 0f b7 16 8d 74 56 02 75 f2 3b f0 72 08}  //weight: 2, accuracy: Low
        $x_1_2 = "\\UpanZhongMa\\Release\\UpanZhongMa.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


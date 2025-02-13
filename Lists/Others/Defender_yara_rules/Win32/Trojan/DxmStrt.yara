rule Trojan_Win32_DxmStrt_J_2147742689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DxmStrt.J!ibt"
        threat_id = "2147742689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DxmStrt"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "svchost.Resources" ascii //weight: 1
        $x_1_2 = "dxmwv" wide //weight: 1
        $x_1_3 = "AntiTaskManagerKill" ascii //weight: 1
        $x_1_4 = {2b 43 03 28 29 00 00 0a 80 07 00 00 04 7e 07 00 00 04 8e b7 16 fe 02 0b 07 2c 12 72 ?? 00 00 70 28 31 00 00 0a 28 32 00 00 0a 00 2b 16 00 73 33 00 00 0a 0a 06 02 6f 34 00 00 0a 00 06 28 35 00 00 0a 26 00 00 17 0b 07 2d b8 00 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


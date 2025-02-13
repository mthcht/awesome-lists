rule TrojanSpy_Win32_Westnet_A_2147682514_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Westnet.A"
        threat_id = "2147682514"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Westnet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 db 80 bd ?? ?? ff ff 5c 75 09 80 bd ?? ?? ff ff 4b 74 ?? e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10}  //weight: 1, accuracy: Low
        $x_1_2 = {63 6f 6f 6b 69 65 [0-16] 70 61 79 70 61 6c 2e [0-16] 6c 6f 67 69 6e 5f 65 6d 61 69 6c}  //weight: 1, accuracy: Low
        $x_1_3 = ".mypen.is" ascii //weight: 1
        $x_1_4 = "config.asia" ascii //weight: 1
        $x_4_5 = {2f 31 2f 31 2e 70 68 70 3f 71 3d 31 26 61 3d 35 00 2e 65 78 65 00 [0-21] 68 74 74 70 73 3a 2f 2f}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


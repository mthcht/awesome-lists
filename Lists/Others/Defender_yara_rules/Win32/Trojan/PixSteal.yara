rule Trojan_Win32_Pixsteal_B_2147678677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pixsteal.B"
        threat_id = "2147678677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pixsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {66 6f 72 20 2f 72 20 ?? 3a 5c 20 25 78 20 69 6e [0-9] 2a 2e 6a 70 67 [0-19] 64 6f 20 63 6f 70 79 20 2f 79 20 25 78 20 43 3a 5c}  //weight: 4, accuracy: Low
        $x_3_2 = "@garitrans.cl" ascii //weight: 3
        $x_2_3 = "66.7.198.240" ascii //weight: 2
        $x_1_4 = "WinRAR.exe a %x .Download.exe" ascii //weight: 1
        $x_1_5 = "netsh firewall set opmode disable" ascii //weight: 1
        $x_1_6 = "c:\\%d-file%d.bmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}


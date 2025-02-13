rule Trojan_Win32_Yalogger_A_2147667430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yalogger.A"
        threat_id = "2147667430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yalogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "HOW!! V2.00==> USER=%s PASS=%s [ IP=%s ComputerName=%s UserName=%s Attacked=%d/%d/%d ]" ascii //weight: 4
        $x_1_2 = "ymsgr:SendIM?" ascii //weight: 1
        $x_1_3 = "kkkeeeyyyllloooggg.bin" ascii //weight: 1
        $x_4_4 = "__C4A38EF4_2234_4035_B1D4_8BA0D4182178__" ascii //weight: 4
        $x_1_5 = {66 6c 61 73 68 00 00 00 42 49 4e 00 77 69 6e 6c 67 6f 6e 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}


rule Trojan_Win32_BlackMould_B_2147746177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackMould.B!dha"
        threat_id = "2147746177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackMould"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "0628182016134805143312" ascii //weight: 3
        $x_2_2 = "Microsoft.Soft" ascii //weight: 2
        $x_2_3 = "[CheckValue]:" ascii //weight: 2
        $x_1_4 = "srvhttp.log" ascii //weight: 1
        $x_1_5 = "ERROR://" ascii //weight: 1
        $x_1_6 = "Rename File Fail." ascii //weight: 1
        $x_1_7 = "hello!!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}


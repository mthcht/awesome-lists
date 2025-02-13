rule Trojan_Win32_Lickore_A_2147646071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lickore.A"
        threat_id = "2147646071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lickore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "enjoy-find.com/index.html?ac=" ascii //weight: 1
        $x_1_2 = "click.linkprice.com/click.php?m=" ascii //weight: 1
        $x_1_3 = "ilikeclick.com/track" ascii //weight: 1
        $x_2_4 = {85 c9 74 19 8b 06 83 78 f4 00 7c 11 51 50 e8 ?? ?? 01 00 83 c4 08 85 c0 74 03 2b 06 c3}  //weight: 2, accuracy: Low
        $x_2_5 = {8b 08 8b 11 50 8b 42 04 ff d0 8b 5c 24 14 83 7b f4 00 0f 8c d5 00 00 00}  //weight: 2, accuracy: High
        $x_2_6 = {8d 70 10 83 c4 04 89 74 24 14 c6 84 24 ?? ?? ?? ?? 07 83 7e f4 00 0f 8c 94 12 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lickore_B_2147655858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lickore.B"
        threat_id = "2147655858"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lickore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 55 f4 b1 01 8b 45 f8 e8 ?? ?? ?? ?? 84 c0 74 ?? 8b 45 f8 e8 ?? ?? ?? ?? ba 00 00 00 80 8b 45 f8 e8 ?? ?? ?? ?? 8d 45 f0}  //weight: 2, accuracy: Low
        $x_1_2 = "clickstory.co.kr/?" ascii //weight: 1
        $x_1_3 = "click.linkprice.com/click.php?m=" ascii //weight: 1
        $x_1_4 = {6a 61 76 61 73 63 72 69 70 74 3a [0-32] 61 62 6f 75 74 3a 62 6c 61 6e 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


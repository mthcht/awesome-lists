rule Trojan_Win32_Phyiost_A_2147626539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phyiost.A"
        threat_id = "2147626539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phyiost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 ad 66 35 ?? ?? 66 ab 4e 4f 66 81 3e ?? ?? 75 ef}  //weight: 2, accuracy: Low
        $x_1_2 = {c1 c2 03 32 10 40 80 38 00 75 f5 57 39 17 75 14}  //weight: 1, accuracy: High
        $x_1_3 = {73 72 73 76 63 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 1, accuracy: High
        $x_1_4 = "accept: */*" ascii //weight: 1
        $x_1_5 = "}aae/::" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Phyiost_B_2147634169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phyiost.B"
        threat_id = "2147634169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phyiost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sfc_os.dll" ascii //weight: 1
        $x_1_2 = "cmd /c net start srservic" ascii //weight: 1
        $x_1_3 = "cmd /c ren " ascii //weight: 1
        $x_1_4 = {c7 07 64 6c 6c 63 83 c7 04 c7 07 61 63 68 65 83 c7 04 c7 07 5c 73 72 73 83 c7 04 c7 07 76 63 2e 64 83 c7 04 66 c7 07 6c 6c 83 c7 02 c6 07 00 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 3d ?? ?? ?? ?? 8d 35 ?? ?? ?? ?? b9 0b 00 00 00 f3 a4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


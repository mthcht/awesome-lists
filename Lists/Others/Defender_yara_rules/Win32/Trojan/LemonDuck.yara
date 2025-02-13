rule Trojan_Win32_LemonDuck_A_2147777720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LemonDuck.A"
        threat_id = "2147777720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LemonDuck"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "schtasks create" ascii //weight: 1
        $x_1_2 = "/ru system" ascii //weight: 1
        $x_1_3 = "/sc MINUTE /mo" ascii //weight: 1
        $x_4_4 = "/tn blackball /F /tr \"blackball\"" ascii //weight: 4
        $x_4_5 = "/tn bluetea /F /tr \"bluetea\"" ascii //weight: 4
        $x_4_6 = {2f 74 6e 20 52 74 73 61 [0-2] 20 2f 46 20 2f 74 72 20 22 70 6f 77 65 72 73 68 65 6c 6c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}


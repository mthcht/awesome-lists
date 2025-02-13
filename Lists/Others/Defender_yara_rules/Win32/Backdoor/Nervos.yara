rule Backdoor_Win32_Nervos_A_2147633720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nervos.A"
        threat_id = "2147633720"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nervos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 a4 32 de a6 8b e8}  //weight: 2, accuracy: High
        $x_2_2 = {80 3e 78 75 3d 80 7e 01 78 75 37 80 7e 02 78 75 31 38 5e 03}  //weight: 2, accuracy: High
        $x_1_3 = " allowedprogram \"%s\"" ascii //weight: 1
        $x_1_4 = "NF:%i,%X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


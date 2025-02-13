rule Worm_Win32_Ahkarun_A_2147608449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ahkarun.A"
        threat_id = "2147608449"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ahkarun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4f 6e 4d 65 73 73 61 67 65 28 30 78 32 31 39 2c 20 22 64 65 67 69 73 69 6b 6c 69 6b 22 29 0d 0a 52 65 74 75 72 6e}  //weight: 1, accuracy: High
        $x_1_2 = {46 69 6c 65 41 70 70 65 6e 64 2c 0d 0a 28 0d 0a 5b 61 75 74 6f 72 75 6e 5d 0d 0a 4f 50 45 4e 3d 65 78 70 6c 6f 72 65 72 2e 65 78 65 0d 0a}  //weight: 1, accuracy: High
        $x_1_3 = {2c 20 4c 69 73 74 2c 20 52 45 4d 4f 56 41 42 4c 45 0d 0a 46 69 6c 65 44 65 6c 65 74 65 2c 20 25 57 69 6e 64 69 72 25 5c 74 65 6d 70 5c 6f 75 74 70 75 74 2e 74 6d 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Ahkarun_A_2147608449_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ahkarun.A"
        threat_id = "2147608449"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ahkarun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Run,%comspec% /c Blat - -body \"bende buradayim\" -subject %dis_ip% -to %kime% -u %kullanici_adi% -pw %sifre%, ,hide" ascii //weight: 2
        $x_1_2 = {25 73 75 72 75 63 75 5f 69 73 69 6d 6c 65 72 69 25 20 0d 0a 29 2c 20 25 57 69 6e 64 69 72 25 5c 74 65 6d 70 5c 6f 75 74 70 75 74 2e 74 6d 70 20 0d 0a 46 69 6c 65 52 65 61 64 2c}  //weight: 1, accuracy: High
        $x_1_3 = {73 69 66 72 65 20 3d 73 61 6e 61 6e 65 0d 0a 52 75 6e 2c 25 63 6f 6d 73 70 65 63 25}  //weight: 1, accuracy: High
        $x_1_4 = {54 45 4d 50 5c 69 70 2e 74 6d 70 0d 0a 55 72 6c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 2c 68 74 74 70 3a 2f 2f 77 77 77 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}


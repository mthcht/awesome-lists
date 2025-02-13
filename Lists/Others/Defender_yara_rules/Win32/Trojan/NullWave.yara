rule Trojan_Win32_NullWave_A_2147831314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NullWave.A!dha"
        threat_id = "2147831314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NullWave"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fd ac fe 8c 06 cd ac e9 d0 4f 7e 10 fb 35 41 56}  //weight: 1, accuracy: High
        $x_1_2 = {ac ac e7 da 4d 9f a0 ea cb 3e 79 06 d7 6e 43 54}  //weight: 1, accuracy: High
        $x_1_3 = {99 7a e0 80 af 2a 36 6a 27 d5 a4 c0 db}  //weight: 1, accuracy: High
        $x_1_4 = {a5 32 f3 dc a1 79 18 25 72 f9 bb c6 f4 b5 8b 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_NullWave_B_2147831315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NullWave.B!dha"
        threat_id = "2147831315"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NullWave"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "Screenlimitsdevices#77!" ascii //weight: 3
        $x_3_2 = {54 68 65 20 66 6f 72 6d 61 74 20 6f 66 20 74 68 65 20 [0-5] 20 66 69 6c 65 20 69 6e 20 6e 6f 74 20 76 61 6c 69 64 2e 0d 0a 28 31 2c 32 29 3a 3a 45 72 72 6f 72 3a 20 69 6e 63 6f 72 72 65 63 74 20 64 6f 63 75 6d 65 6e 74 20 73 79 6e 74 61 78}  //weight: 3, accuracy: Low
        $x_1_3 = "C:\\HI%c" wide //weight: 1
        $x_1_4 = "%s\\*.*" wide //weight: 1
        $x_1_5 = "All Files (*.*)" ascii //weight: 1
        $x_1_6 = "%s\\sysnative\\" ascii //weight: 1
        $x_1_7 = "%s%C%C%X-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}


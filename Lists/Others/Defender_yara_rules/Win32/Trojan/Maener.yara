rule Trojan_Win32_Maener_A_2147688776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Maener.A"
        threat_id = "2147688776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Maener"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "miner_exe_name" ascii //weight: 1
        $x_1_2 = "mining_info" ascii //weight: 1
        $x_3_3 = "tools/RegWriter.exe" ascii //weight: 3
        $x_5_4 = "SamaelLovesMe" ascii //weight: 5
        $x_5_5 = {8b c3 c1 e8 10 88 06 8b c3 c1 e8 08 88 46 01 88 5e 02 83 c6 03 bb 01 00 00 00}  //weight: 5, accuracy: High
        $x_5_6 = {68 74 74 70 3a 2f 2f 31 2e [0-16] 2e 7a 38 2e 72 75 2f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Maener_B_2147691522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Maener.B"
        threat_id = "2147691522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Maener"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 61 75 6d 2d [0-5] 77 69 74 68 [0-5] 4d 65}  //weight: 1, accuracy: Low
        $x_1_2 = "tools/regwrite.raum_encrypted" ascii //weight: 1
        $x_1_3 = {6d 69 6e 69 6e 67 5f 69 6e 66 6f 00 75 70 64 61 74 65 5f 69 6e 66 6f}  //weight: 1, accuracy: High
        $x_1_4 = {36 34 62 69 74 [0-5] 33 32 62 69 74}  //weight: 1, accuracy: Low
        $x_1_5 = {53 74 6f 70 70 65 72 2d 6d 75 74 65 78 [0-5] 50 47 68 30 62 57 77 3d [0-5] 5c 62 69 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Maener_MKV_2147920052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Maener.MKV!MTB"
        threat_id = "2147920052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Maener"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b c1 33 d2 f7 75 ec 41 8a 82 ?? ?? ?? ?? 30 44 31 ff 3b cf 72 ea 83 ec 0c 8d 8d 88 fe ff ff 53 e8}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


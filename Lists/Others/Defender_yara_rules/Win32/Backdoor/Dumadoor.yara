rule Backdoor_Win32_Dumadoor_BM_2147605079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dumadoor.BM"
        threat_id = "2147605079"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dumadoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\dvp.log" ascii //weight: 1
        $x_1_2 = "\\SYSTEM32\\DRIVERS\\ETC\\hosts" ascii //weight: 1
        $x_1_3 = {61 80 38 6c 75 29 80 78 01 6f 75 23 80 78 02 67 75 1d 80 78 03 64 75 17 80 78 04 61 75 11 80 78 05 74 75 0b 80 78 06 61 75 05}  //weight: 1, accuracy: High
        $x_5_4 = {83 c6 0a ac 3c 2f 75 2e 83 c1 02 89 0d ?? ?? ?? ?? c6 46 ff 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 01 59 e2 cb 68 ?? ?? ?? ?? 6a 02}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Dumadoor_BN_2147605080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dumadoor.BN"
        threat_id = "2147605080"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dumadoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ocks/bot" ascii //weight: 1
        $x_1_2 = "&machineid=" ascii //weight: 1
        $x_1_3 = "Software\\SARS" ascii //weight: 1
        $x_1_4 = "?cmd_alarm=" ascii //weight: 1
        $x_1_5 = "ftppassword:" ascii //weight: 1
        $x_1_6 = "\\netdx.dat" ascii //weight: 1
        $x_1_7 = "\\wmplayer.exe" ascii //weight: 1
        $x_2_8 = {8b 44 24 08 81 ec ac 01 00 00 83 e8 00 0f ?? ?? 00 00 00 48 0f ?? ?? 00 00 00 56 57 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 0c 89 44 24 ?? 8b 44 24 ?? 8b 00 89 44 24 ?? 8b ?? ?? ?? ?? ?? 8d 44 24 ?? 50}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Dumadoor_A_2147653664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dumadoor.A"
        threat_id = "2147653664"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dumadoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 75 72 6c 2e 64 61 74 00 5c 64 76 70 64 2e 64 6c 6c 00 4d 48 6f 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 6c 6f 61 64 33 32 00 53 6f 66 74 77 61 72 65 5c 53 41 52 53 5c 00 5c 6e 65 74 64 78 2e 64 61 74}  //weight: 1, accuracy: High
        $x_1_3 = {6d 61 69 6c 73 65 6e 64 65 64 00 ?? 00 5c 73 65 6e 64 5f 6c 6f 67 73 5f 74 72 69 67 67 65 72 00 5c 64 76 70 2e 6c 6f 67}  //weight: 1, accuracy: Low
        $x_1_4 = "scam_page_url" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Ransom_Win32_Mytreex_A_2147720789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mytreex.A"
        threat_id = "2147720789"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mytreex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ADMIN_NO|INT_" ascii //weight: 1
        $x_1_2 = "ADMIN_YES|INT_" ascii //weight: 1
        $x_1_3 = "CIP_STARTED" ascii //weight: 1
        $x_1_4 = "MASTER_STARTED" ascii //weight: 1
        $x_1_5 = "BroSt:" ascii //weight: 1
        $x_1_6 = "FixLnk:" ascii //weight: 1
        $x_1_7 = "GetRdm:" ascii //weight: 1
        $x_1_8 = "Mcpy:" ascii //weight: 1
        $x_1_9 = "MTch:" ascii //weight: 1
        $x_1_10 = "[ND_START]" ascii //weight: 1
        $x_1_11 = "[NF_END]" ascii //weight: 1
        $x_1_12 = "\"%TEMP%\\[EXE_NAME]\"" ascii //weight: 1
        $x_1_13 = "\"[TO_PATH]\" [PARAMS]" ascii //weight: 1
        $x_2_14 = "\\Run\" /v \"[HTA_NAME]\" /t REG_SZ /f /d \"\\\"[HTA_PATH]\"\\\"" ascii //weight: 2
        $x_2_15 = "\\Shell Icons\" /v \"29\" /t REG_SZ /f /d \"[ICO_PATH],0\"" ascii //weight: 2
        $x_1_16 = "+h \"[TO_DIR]\"" ascii //weight: 1
        $x_1_17 = "+h \"[TO_PATH]\"" ascii //weight: 1
        $x_1_18 = "-r -s -h \"[TO_PATH]\"" ascii //weight: 1
        $x_1_19 = "\"[FILENAME]\" /E /G %USERNAME%:F /C" ascii //weight: 1
        $x_1_20 = "/f /q \"[TO_PATH]\"" ascii //weight: 1
        $x_2_21 = "\"[DIR_NAME]\\[HID_NAME]\" > \"%TEMP%\\[EXE_NAME]\"" ascii //weight: 2
        $x_2_22 = "\"[FROM_PATH]\" > \"[TO_PATH]\"" ascii //weight: 2
        $x_1_23 = {83 f8 02 74 0a 83 f8 03 74 05 83 f8 04 75 ?? 8d 45 f4 8b d3 e8 ?? ?? ?? ?? 8d 45 f4 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 f4 8b 06 8b 08 ff 51 3c 4b 83 fb 42 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Mytreex_B_2147720859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mytreex.B!rsm"
        threat_id = "2147720859"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mytreex"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "210"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {68 a0 04 04 00 6a 00 ff 15}  //weight: 100, accuracy: High
        $x_100_2 = {6a 40 68 a0 04 04 00 [0-8] ff 15}  //weight: 100, accuracy: Low
        $x_10_3 = {b9 79 37 9e}  //weight: 10, accuracy: High
        $x_10_4 = {47 86 c8 61}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}


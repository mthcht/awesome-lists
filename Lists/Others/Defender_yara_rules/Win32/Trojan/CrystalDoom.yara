rule Trojan_Win32_CrystalDoom_A_2147725046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CrystalDoom.A!dha"
        threat_id = "2147725046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CrystalDoom"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 53 61 66 65 41 70 70 65 6e 64 50 72 6f 67 72 61 6d 4d 6f 64}  //weight: 1, accuracy: High
        $x_1_2 = {00 47 65 74 43 70 53 74 61 74 75 73 28}  //weight: 1, accuracy: High
        $x_1_3 = {00 54 73 41 70 69 74}  //weight: 1, accuracy: High
        $x_1_4 = {00 73 63 72 69 70 74 5f 63 6f 64 65}  //weight: 1, accuracy: High
        $x_1_5 = {00 73 63 72 69 70 74 5f 74 65 73 74 2e 70 79 74}  //weight: 1, accuracy: High
        $x_1_6 = {00 50 72 65 73 65 74 53 74 61 74 75 73 46 69 65 6c 64}  //weight: 1, accuracy: High
        $x_1_7 = {00 55 70 6c 6f 61 64 44 75 6d 6d 79 46 6f 72 63 65}  //weight: 1, accuracy: High
        $x_1_8 = {00 75 6e 61 62 6c 65 20 74 6f 20 63 6f 6e 6e 65 63 74 21}  //weight: 1, accuracy: High
        $x_1_9 = {00 69 6e 6a 65 63 74 2e 62 69 6e}  //weight: 1, accuracy: High
        $x_1_10 = {00 69 6d 61 69 6e 2e 62 69 6e}  //weight: 1, accuracy: High
        $x_1_11 = {00 6d 6f 64 75 6c 65 20 66 69 6c 65 20 72 65 61 64 20 46 41 49 4c 55 52 45}  //weight: 1, accuracy: High
        $x_1_12 = {00 73 65 74 74 69 6e 67 20 61 72 67 75 6d 65 6e 74 73 2e 2e 2e}  //weight: 1, accuracy: High
        $x_1_13 = {00 50 72 65 73 65 74 20 66 61 69 6c 75 72 65}  //weight: 1, accuracy: High
        $x_1_14 = {00 6d 61 69 6e 20 63 6f 64 65 20 77 72 69 74 65 20 46 41 49 4c 45 44 21}  //weight: 1, accuracy: High
        $x_1_15 = {00 4d 50 20 42 61 64 20 53 74 61 74 65 21}  //weight: 1, accuracy: High
        $x_1_16 = {00 63 6f 75 6e 74 64 6f 77 6e 3a 20 25 64}  //weight: 1, accuracy: High
        $x_1_17 = {00 53 63 72 69 70 74 20 68 61 73 20 73 74 6f 70 70 65 64}  //weight: 1, accuracy: High
        $x_1_18 = {00 53 63 72 69 70 74 20 53 55 43 43 45 53 53}  //weight: 1, accuracy: High
        $x_1_19 = {00 53 63 72 69 70 74 20 46 41 49 4c 45 44}  //weight: 1, accuracy: High
        $x_1_20 = {00 66 6f 72 63 65 20 72 65 6d 6f 76 69 6e 67 20 74 68 65 20 63 6f 64 65 2c 20 6e 6f 20 63 68 65 63 6b 73}  //weight: 1, accuracy: High
        $x_1_21 = {00 72 65 73 74 6f 72 65 20 6e 6f 74 20 72 65 71 75 69 72 65 64}  //weight: 1, accuracy: High
        $x_1_22 = {00 54 73 48 69}  //weight: 1, accuracy: High
        $x_1_23 = {00 63 6f 6e 6e 65 63 74 5f 72 65 73 75 6c 74}  //weight: 1, accuracy: High
        $x_1_24 = {00 73 63 72 69 70 74 5f 63 6f 64 65 74}  //weight: 1, accuracy: High
        $x_1_25 = {00 63 6f 6e 73 6f 6c 65 5f 65 78 65 00}  //weight: 1, accuracy: High
        $x_5_26 = {ff ff 60 38 02 00 00 44 20 00 80 4e}  //weight: 5, accuracy: High
        $x_5_27 = {40 3c 00 00 62 80 40 00 80 3c 40 20 03 7c 1c 00 82 40 04 00 62 80 60 00 80 3c 40 20 03 7c 0c 00 82 40 18 00 42 38 1c 00 00 48 80 00 80 3c 00 01 84 60 40 20 02 7c 18 00 80 40 04 00 42 38 c4 ff ff 4b}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CrystalDoom_B_2147725083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CrystalDoom.B!dha"
        threat_id = "2147725083"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CrystalDoom"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "import Ts" ascii //weight: 1
        $x_1_2 = "def ts_" ascii //weight: 1
        $x_1_3 = "TS_cnames.py" ascii //weight: 1
        $x_1_4 = "TRICON" ascii //weight: 1
        $x_1_5 = "TriStation " ascii //weight: 1
        $x_1_6 = " chassis " ascii //weight: 1
        $x_1_7 = "GetCpStatus" ascii //weight: 1
        $x_1_8 = "import TsHi" ascii //weight: 1
        $x_1_9 = "import TsLow" ascii //weight: 1
        $x_1_10 = "import TsBase" ascii //weight: 1
        $x_1_11 = {6d 6f 64 75 6c 65 ?? 76 65 72 73 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_12 = "prog_cnt" ascii //weight: 1
        $x_1_13 = "TsBase.py" ascii //weight: 1
        $x_1_14 = ".TsBase(" ascii //weight: 1
        $x_1_15 = "TsHi.py" ascii //weight: 1
        $x_1_16 = "keystate" ascii //weight: 1
        $x_1_17 = "GetProjectInfo" ascii //weight: 1
        $x_1_18 = "GetProgramTable" ascii //weight: 1
        $x_1_19 = "SafeAppendProgramMod" ascii //weight: 1
        $x_1_20 = ".TsHi(" ascii //weight: 1
        $x_1_21 = "TsLow.py" ascii //weight: 1
        $x_1_22 = "print_last_error" ascii //weight: 1
        $x_1_23 = ".TsLow(" ascii //weight: 1
        $x_1_24 = " TCM found" ascii //weight: 1
        $x_1_25 = "CRC16_MODBUS" ascii //weight: 1
        $x_1_26 = "Kotov Alaxander" ascii //weight: 1
        $x_1_27 = "CRC_CCITT_XMODEM" ascii //weight: 1
        $x_1_28 = "crc16ret" ascii //weight: 1
        $x_1_29 = "CRC16_CCITT" ascii //weight: 1
        $x_1_30 = "sh.pyc" ascii //weight: 1
        $x_1_31 = " FAILURE" ascii //weight: 1
        $x_1_32 = "symbol table" ascii //weight: 1
        $x_1_33 = "inject.bin" ascii //weight: 1
        $x_1_34 = "imain.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}


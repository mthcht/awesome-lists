rule TrojanSpy_MSIL_Keylog_A_2147663203_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylog.A"
        threat_id = "2147663203"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "King Kong Keylogger" wide //weight: 5
        $x_5_2 = "Keylogger Log" wide //weight: 5
        $x_5_3 = {00 73 68 69 66 74 61 6e 64 63 61 70 73 00}  //weight: 5, accuracy: High
        $x_15_4 = {00 4b 65 79 62 6f 61 72 64 50 72 6f 63 00}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_Keylog_B_2147663214_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylog.B"
        threat_id = "2147663214"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Reflect Logger" wide //weight: 5
        $x_15_2 = "KECABA" ascii //weight: 15
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylog_B_2147663214_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylog.B"
        threat_id = "2147663214"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HawkEye Keylogger - Reborn" wide //weight: 1
        $x_1_2 = "http://pomf.cat" wide //weight: 1
        $x_1_3 = "Reborn Stub.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylog_E_2147664327_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylog.E"
        threat_id = "2147664327"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 44 41 43 68 72 6f 6d 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 44 41 4f 70 65 72 61 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 44 41 53 74 65 61 6d 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 44 41 4d 65 6c 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 44 41 53 74 61 72 74 75 70 00}  //weight: 1, accuracy: High
        $x_15_6 = {00 4b 59 42 52 44 4c 43 4b 00}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_Keylog_E_2147664327_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylog.E"
        threat_id = "2147664327"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 59 61 68 6f 6f 53 70 [0-3] 64 64 6c 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 53 6b 79 70 65 53 70 [0-3] 64 64 6c 6c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6b 00 5a 00 33 00 45 00 78 00 63 00 61 00 6b 00 77 00 38 00 72 00 49 00 79 00 4a 00 47 00 54 00 7a 00 63 00 65 00 34 00 6d 00 72 00 37 00 50 00 79 00 37 00 57 00 68 00 77 00 37 00 63 00 55 00 00 0d 2a 00 2e 00 70 00 6e 00 67 00 2a 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {72 53 74 75 62 5c 4c 69 6d 69 74 6c 65 73 73 4c 6f 67 67 65 72 53 74 75 62 5c 6f 62 6a 5c 78 38 36 5c 44 65 62 75 67 5c 4c 4c 53 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_5 = {6b 65 79 63 68 61 69 6e 00 53 61 66 47 65 74 00 44 65 63 72 79 70 74 50 61 73 73 77 6f 72 64 00 70 77 42 75 66 66 65 72 00 43 6f 6e 76 65 72 74}  //weight: 1, accuracy: High
        $x_1_6 = {56 4b 43 4f 00 53 43 43 4f 00 46 4c 47 53 00 54 49 45 4d 00 44 57 45 58 49 4e 00}  //weight: 1, accuracy: High
        $x_1_7 = {4b 59 42 52 44 4c 43 4b 00 43 6f 64 65 00 57 50 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_MSIL_Keylog_E_2147664327_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylog.E"
        threat_id = "2147664327"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "YpqprKmClq+2VWmloaShe6OvY3uIoKl9VTA=" wide //weight: 5
        $x_5_2 = "lZGdpJZ3kp2klneSnaSWd5KdpJZ3kp2klneSnaSWd5KdpJZ3kp2klneSnaSWd5KdpJZ3krPbvpvBxdnMd5KdpJZ3kp2klneSnaSWd5K" wide //weight: 5
        $x_1_3 = {00 4b 59 42 52 44 4c 43 4b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_Keylog_G_2147666863_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylog.G"
        threat_id = "2147666863"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 17 8d 01 00 00 01 0b 07 16 72 ?? ?? ?? ?? 28 ?? ?? 00 06 28 ?? ?? 00 0a 6f ?? ?? 00 0a 28 ?? ?? 00 0a 17 8d 11 00 00 01 0c 08}  //weight: 1, accuracy: Low
        $x_1_2 = {49 6e 76 6f 6b 65 00 72 61 6e 64 6f 6d}  //weight: 1, accuracy: High
        $x_1_3 = "ControlME" ascii //weight: 1
        $x_1_4 = "|qwertyasdfzx" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylog_I_2147679618_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylog.I"
        threat_id = "2147679618"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 48 4f 4f 4b 45 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 54 68 79 53 65 6e 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 44 65 63 72 79 70 74 44 61 74 61 00}  //weight: 1, accuracy: High
        $x_15_4 = {00 4b 45 43 41 42 41 00}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Keylog_AB_2147684200_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylog.AB"
        threat_id = "2147684200"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/config.php" wide //weight: 1
        $x_1_2 = "/upload.php" wide //weight: 1
        $x_1_3 = ".tmp" wide //weight: 1
        $x_1_4 = "image/jpeg" wide //weight: 1
        $x_1_5 = "SendScreen" ascii //weight: 1
        $x_1_6 = "keybd_event" ascii //weight: 1
        $x_2_7 = "C:\\systmp.tmp" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_Keylog_AC_2147719013_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Keylog.AC!bit"
        threat_id = "2147719013"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylog"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 61 6c 66 4d 65 6c 74 00 72 63 34}  //weight: 1, accuracy: High
        $x_1_2 = {6e 6f 6e 75 62 00 4d 65 6c 74}  //weight: 1, accuracy: High
        $x_1_3 = {47 65 74 53 74 65 61 6d 55 73 65 72 6e 61 6d 65 00 41 64 64 53 74 61 72 74 75 70}  //weight: 1, accuracy: High
        $x_1_4 = {4d 61 69 6e 4c 6f 6f 70 00 43 6f 6e 6e 65 63 74 00 50 72 6f 63 65 73 73 43 6f 6d 6d 61 6e 64 73}  //weight: 1, accuracy: High
        $x_1_5 = "shiftandcaps" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


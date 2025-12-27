rule Trojan_Win32_DefendNot_Z_2147952388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DefendNot.Z"
        threat_id = "2147952388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DefendNot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "defendnot::" ascii //weight: 2
        $x_2_2 = "defender-disabler-ipc" ascii //weight: 2
        $x_1_3 = "AV Name can not be empty!" ascii //weight: 1
        $x_1_4 = "IWscASStatus" ascii //weight: 1
        $x_1_5 = "IWscAVStatus4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_DefendNot_X_2147952390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DefendNot.X"
        threat_id = "2147952390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DefendNot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "206"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {37 2c 10 f2 c3 90 0c 45 b3 f6 92 be 16 93 bd f2}  //weight: 100, accuracy: High
        $x_100_2 = {56 97 4e 02 6c ba d1 4a 83 21 87 ba e7 8f d0 e3}  //weight: 100, accuracy: High
        $x_1_3 = {ac af cb 4d ba 29 b1 46 80 fc b8 bd e3 c0 ae 4d}  //weight: 1, accuracy: High
        $x_1_4 = {65 a7 01 39 91 ab a9 4b a5 53 5b 85 38 de b8 40}  //weight: 1, accuracy: High
        $x_1_5 = {a2 7c 00 cf e3 f5 e5 11 9c e9 5e 55 17 50 7c 66}  //weight: 1, accuracy: High
        $x_1_6 = {54 01 04 80 10 00 ff 15}  //weight: 1, accuracy: Low
        $x_5_7 = "AV Name can not be empty!" ascii //weight: 5
        $x_5_8 = "delaying for com retry" ascii //weight: 5
        $x_5_9 = "{}_register: {:#x}" ascii //weight: 5
        $x_10_10 = "defendnot::" ascii //weight: 10
        $x_10_11 = "defender-disabler-ipc" ascii //weight: 10
        $x_10_12 = "ctx.bin" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*) and 2 of ($x_5_*))) or
            ((2 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}


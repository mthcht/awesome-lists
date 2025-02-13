rule Trojan_Win32_Hostblock_P_2147616556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hostblock.P"
        threat_id = "2147616556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hostblock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\system32\\drivers\\etc\\hosts" ascii //weight: 10
        $x_10_2 = "127.0.0.1 www.videogaga.lt" ascii //weight: 10
        $x_10_3 = "127.0.0.1 videogaga.lt" ascii //weight: 10
        $x_10_4 = {ff ff ff ff 0b 00 00 00 31 32 37 2e 30 2e 30 2e 31 20 63 00 ff ff ff ff 07 00 00 00 2e 6f 6e 65 2e 6c 74 00 ff ff ff ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hostblock_T_2147626099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hostblock.T"
        threat_id = "2147626099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hostblock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Administrador\\Escritorio\\seko\\exeseko\\HHHH.vbp" wide //weight: 1
        $x_1_2 = "C:\\WINDOWS\\system32\\drivers\\etc\\hosts" wide //weight: 1
        $x_1_3 = "http://gusanito.com.xcolv.com/postalesterra/sko.php" wide //weight: 1
        $x_1_4 = {4e 00 6f 00 20 00 73 00 65 00 20 00 65 00 6e 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 20 00 6c 00 61 00 20 00 6c 00 69 00 62 00 72 00 65 00 72 00 69 00 61 00 20 00 73 00 69 00 73 00 74 00 65 00 6d 00 33 00 32 00 52 00 75 00 6d 00 2e 00 64 00 6c 00 6c 00 20 00 21 00 00 00 00 00 1c 00 00 00 65 00 72 00 72 00 6f 00 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hostblock_V_2147643759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hostblock.V"
        threat_id = "2147643759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hostblock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 32 37 2e 30 2e 30 2e 31 09 00}  //weight: 10, accuracy: High
        $x_10_2 = "\\drivers\\etc\\hosts" ascii //weight: 10
        $x_10_3 = {0f b6 56 28 8b 46 24 8a 92 ?? ?? ?? ?? 30 14 08 ?? ?? 28 03 c1 80 7e 28 2e 76 04 c6 46 28 00 [0-2] 3b 4e 10 72}  //weight: 10, accuracy: Low
        $x_1_4 = "Please, run this program as Administrator!" wide //weight: 1
        $x_1_5 = "ovLzc3LjIyMS4xNTMuMTcwL3Rlc3QucGhwP2tleT0qwert" ascii //weight: 1
        $x_1_6 = "sdfkjvnsldkfjvn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


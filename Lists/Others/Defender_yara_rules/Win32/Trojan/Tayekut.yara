rule Trojan_Win32_Tayekut_A_2147753703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tayekut.A"
        threat_id = "2147753703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tayekut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 28 00}  //weight: 1, accuracy: Low
        $x_1_2 = "createobject(" wide //weight: 1
        $x_1_3 = "wscript.shell" wide //weight: 1
        $x_1_4 = ").run" wide //weight: 1
        $x_1_5 = ")(window.close)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tayekut_B_2147753704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tayekut.B"
        threat_id = "2147753704"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tayekut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 28 00}  //weight: 1, accuracy: Low
        $x_1_2 = "createobject(" wide //weight: 1
        $x_1_3 = "wscript.shell" wide //weight: 1
        $x_1_4 = ").run" wide //weight: 1
        $x_1_5 = "powershell" wide //weight: 1
        $x_1_6 = "-noexit" wide //weight: 1
        $x_1_7 = "-file" wide //weight: 1
        $x_1_8 = ":close)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tayekut_C_2147762680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tayekut.C"
        threat_id = "2147762680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tayekut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00}  //weight: 1, accuracy: Low
        $x_1_2 = "createobject(" wide //weight: 1
        $x_1_3 = "wscript.shell" wide //weight: 1
        $x_1_4 = ".run" wide //weight: 1
        $x_1_5 = "window.close" wide //weight: 1
        $x_1_6 = "-server" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tayekut_D_2147763301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tayekut.D"
        threat_id = "2147763301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tayekut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00}  //weight: 1, accuracy: Low
        $x_1_2 = "createobject(" wide //weight: 1
        $x_1_3 = "wscript.shell" wide //weight: 1
        $x_1_4 = {2e 00 72 00 75 00 6e 00 28 00 [0-255] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = "window.close" wide //weight: 1
        $n_20_6 = {2e 00 72 00 75 00 6e 00 28 00 90 00 02 00 ff 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00}  //weight: -20, accuracy: High
        $n_20_7 = {2e 00 72 00 75 00 6e 00 28 00 90 00 02 00 ff 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00}  //weight: -20, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_Tayekut_E_2147796282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tayekut.E"
        threat_id = "2147796282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tayekut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00}  //weight: 1, accuracy: Low
        $x_1_2 = "createobject(" wide //weight: 1
        $x_1_3 = "wscript.shell" wide //weight: 1
        $x_1_4 = ".run" wide //weight: 1
        $x_1_5 = "powershell" wide //weight: 1
        $x_1_6 = "-nop" wide //weight: 1
        $x_1_7 = "-exec" wide //weight: 1
        $x_1_8 = "bypass" wide //weight: 1
        $x_1_9 = "-enc" wide //weight: 1
        $x_1_10 = ")(window.close)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tayekut_F_2147796283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tayekut.F"
        threat_id = "2147796283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tayekut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00}  //weight: 1, accuracy: Low
        $x_1_2 = "createobject(" wide //weight: 1
        $x_1_3 = "wscript.shell" wide //weight: 1
        $x_1_4 = ".run" wide //weight: 1
        $x_1_5 = "powershell" wide //weight: 1
        $x_1_6 = "invoke-webrequest" wide //weight: 1
        $x_1_7 = ":close)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


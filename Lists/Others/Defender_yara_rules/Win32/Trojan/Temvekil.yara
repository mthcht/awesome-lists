rule Trojan_Win32_Temvekil_A_2147648038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Temvekil.A"
        threat_id = "2147648038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Temvekil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a d0 80 e2 03 80 c2 4d 30 14 08 40 3b c6 7c}  //weight: 1, accuracy: High
        $x_1_2 = {ba fe ff 00 00 66 01 94 4c 90 00 00 00 41 3b c8 7c}  //weight: 1, accuracy: High
        $x_1_3 = "taskkill /f /im teamviewer.e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Temvekil_B_2147649919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Temvekil.B"
        threat_id = "2147649919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Temvekil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 75 6f 6d 6e 72 67 65 00 00 00 00 65 46 69 6c 65 57}  //weight: 1, accuracy: High
        $x_1_2 = {5c 74 68 75 6d 62 6e 61 69 6c 73 2e 64 62 00 00 2e 00 74 00 6d 00 70}  //weight: 1, accuracy: High
        $x_1_3 = "_N_u_l_l_s_o_f_t_I_n_s_t_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


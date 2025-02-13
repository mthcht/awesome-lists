rule Backdoor_Win32_Slingup_A_2147706512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Slingup.A"
        threat_id = "2147706512"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Slingup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 5f 53 50 41 4d 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 5f 4b 45 59 4c 4f 47 47 45 52 00}  //weight: 1, accuracy: High
        $x_1_3 = {50 5f 44 53 50 52 45 41 44 00}  //weight: 1, accuracy: High
        $x_1_4 = {41 5f 4d 41 4c 57 52 00}  //weight: 1, accuracy: High
        $x_1_5 = {41 5f 53 41 4e 44 00}  //weight: 1, accuracy: High
        $x_1_6 = {50 5f 50 45 52 53 49 53 54 41 4e 43 45 00}  //weight: 1, accuracy: High
        $x_1_7 = "plugins/ddos.p" wide //weight: 1
        $x_1_8 = "plugins/spam.p" wide //weight: 1
        $x_1_9 = "plugins/keylogger.p" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


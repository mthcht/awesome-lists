rule Trojan_Win32_Klibot_A_2147662744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Klibot.A"
        threat_id = "2147662744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Klibot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 44 44 4e 45 57 7c 00 44 44 6f 53 65 72}  //weight: 1, accuracy: High
        $x_1_2 = {49 52 43 20 42 6f 74 00 25 73 7c 25 73 7c 25 64 7c 25 73 7c 25 73}  //weight: 1, accuracy: High
        $x_1_3 = "*paypal.*/webscr?cmd=_login-submit*" ascii //weight: 1
        $x_1_4 = {8a 04 1e 83 c9 ff 30 04 3a 8b fb 33 c0 46 f2 ae f7 d1 49 3b f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


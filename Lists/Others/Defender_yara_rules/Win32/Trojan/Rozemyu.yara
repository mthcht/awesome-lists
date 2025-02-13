rule Trojan_Win32_Rozemyu_A_2147686331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozemyu.A"
        threat_id = "2147686331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozemyu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 5a 6f 72 65 6e 69 75 6d 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = "Global\\Zorenium" wide //weight: 1
        $x_1_3 = {61 00 64 00 64 00 75 00 73 00 65 00 72 00 2e 00 70 00 68 00 70 00 3f 00 75 00 69 00 64 00 3d 00 31 00 33 00 33 00 37 00 26 00 6c 00 61 00 6e 00 3d 00 [0-32] 26 00 63 00 6d 00 70 00 6e 00 61 00 6d 00 65 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_4 = "Register.php?Status=New&UserID=%s&Location=%s&OSVersion=%s&Platform=%s&version=v" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Rozemyu_B_2147686332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozemyu.B"
        threat_id = "2147686332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozemyu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\P2P\\Client\\Debug\\Client.pdb" ascii //weight: 1
        $x_1_2 = "[C&C] (%s) - %s" ascii //weight: 1
        $x_1_3 = "[NakBot] Awaiting UDP Data Connection on %d" ascii //weight: 1
        $x_1_4 = "UDPInit" ascii //weight: 1
        $x_1_5 = {58 45 4e 43 00 00 00 00 58 45 4e 52 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


rule Trojan_Win32_Comroki_A_2147645302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Comroki.A"
        threat_id = "2147645302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Comroki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 65 6e 73 61 67 65 6d 3d 27 49 4e 46 45 43 54 20 42 79 20 43 6f 64 65 72 20 52 6f 6f 74 4b 69 74 00}  //weight: 1, accuracy: High
        $x_1_2 = "Mensagem='New KL_CCs_2011 By Coder_rootkit@htmail.com" ascii //weight: 1
        $x_1_3 = {2e 6c 69 6e 6b 77 73 2e 63 6f 6d 2f 70 72 6f 63 2f 73 75 70 65 72 50 72 6f 63 2e 6a 73 70 00}  //weight: 1, accuracy: High
        $x_1_4 = {4c 53 41 20 53 68 65 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {77 69 6e 64 6f 77 73 20 6d 61 6e 61 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_6 = "userProductID=" ascii //weight: 1
        $x_1_7 = "actionID=" ascii //weight: 1
        $x_1_8 = "Assunto=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_SockSystemz_A_2147923910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SockSystemz.A!MTB"
        threat_id = "2147923910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SockSystemz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 4c 0c 45 23 a1 99 ed 97 58 07 a7 9b e7 b6 bc 31 ff 91 86 6f d0 b9 54 67 2e 48 32 c5 a6 7f 30 cc 4a 22 57 72 d2 be c3 3b eb a7 00 67 87 1f d2 34 1b eb ad 04 72 86 33 c7 aa be d7 da a1 53 d4 ae 6c ad 7f 21 ae 4e 07 e1 63 ac 19 84 3e 8c 7f 12 e7 ed bb bd 38 9c 21 0b 8e 93 ba aa 73 4f 92 9b}  //weight: 1, accuracy: High
        $x_1_2 = {2b 4e 77 31 6c d7 90 16 eb 9e 1e 95 47 b6 ae 4e 72 9a f0 30 cb 0d e8 41 d9 2d 17 dc 3c ce 85 76 05 b4 c2 a0 79 d6 d8 51 be 62 66 e9 96 bf 1d 01 55 e9 22 29 a8 f6 7b ce dc 13 2f 0b bd 2f 10 47 09 a3 c0 b4 30 7b 8a 0d ff c8 1e 9d c2 74 ed 0a 29 64 09 91 be cb 8f 5c 8c 35 41 8c 2f f4 79 40 0a 09 f2 fb 7b ab 03 85 1d ea a5 72 12 e9 f0 b8 c7 0d b9 84 c3 cc a9 66 e2 97 dc fd e9 95 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


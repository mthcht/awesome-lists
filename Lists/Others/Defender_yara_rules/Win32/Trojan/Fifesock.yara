rule Trojan_Win32_Fifesock_C_2147645309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fifesock.gen!C"
        threat_id = "2147645309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fifesock"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "systemsmssrvc" ascii //weight: 1
        $x_1_2 = {69 6e 6a 65 63 74 2e 64 6c 6c 00 43 61 6c 63 48 61 73 68 00}  //weight: 1, accuracy: High
        $x_1_3 = "LoopInject@4" ascii //weight: 1
        $x_1_4 = {c7 44 24 10 40 00 00 00 c7 44 24 0c 00 30 00 00 b8 ?? ?? ?? ?? 2d ?? ?? ?? ?? 89 44 24 08 c7 44 24 04 00 00 00 00 8b 45 ec 89 04 24 a1 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_5 = {eb 05 89 e2 0f 34 c3 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 b8 6c 00 00 00 e8 dd ff ff ff 83 c4 28 8d 80 4e 32 22 51 a3}  //weight: 1, accuracy: High
        $x_1_6 = {66 83 38 00 74 19 8d 45 fc c1 00 07 8b 45 f8 0f b7 10 8d 45 fc 31 10 8d 45 f8 83 00 02 eb de 8b 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


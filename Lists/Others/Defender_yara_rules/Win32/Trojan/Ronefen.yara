rule Trojan_Win32_Ronefen_A_2147749429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ronefen.A!dha"
        threat_id = "2147749429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ronefen"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 77 00 69 00 6e 00 66 00 65 00 6e 00 73 00 65 00 00 00 00 00 00 00 6d 00 73 00 68 00 74 00 61 00 20 00 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 45 00 78 00 65 00 63 00 75 00}  //weight: 1, accuracy: High
        $x_1_2 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 00 00 45 00 6c 00 65 00 76 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 21 00 6e 00 65 00 77 00 3a 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "32 bit payloads can be injected from 32bit load" ascii //weight: 1
        $x_1_4 = "F0E498348C7738AA023E96C89337535EBC248D940CE074E317273230" wide //weight: 1
        $x_1_5 = {77 00 69 00 6e 00 6d 00 67 00 6d 00 74 00 00 00 65 72 72 6f 72 00 00 00 52 00 65 00 61 00 6c 00 74 00 65 00 6b 00 20 00 48 00 44 00 20 00 41 00 75 00 64 00 69 00 6f 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


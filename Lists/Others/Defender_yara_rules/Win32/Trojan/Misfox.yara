rule Trojan_Win32_Misfox_A_2147707657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Misfox.A"
        threat_id = "2147707657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Misfox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c1 25 ff 00 00 00 8a 84 85 f4 fb ff ff 32 47 ff ff 8d e8 fb ff ff 88 44 3b ff 75 ae}  //weight: 1, accuracy: High
        $x_1_2 = {47 45 54 00 2f 6c 61 73 74 2e 73 6f}  //weight: 1, accuracy: High
        $x_1_3 = {5c 52 75 6e 00 00 00 47 6c 6f 62 61 6c 5c 5f 5f 64 65 63 6c 73 70 65 63}  //weight: 1, accuracy: High
        $x_1_4 = "Global\\msiff0x1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Misfox_A_2147717202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Misfox.A!!Misfox.gen!A"
        threat_id = "2147717202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Misfox"
        severity = "Critical"
        info = "Misfox: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c1 25 ff 00 00 00 8a 84 85 f4 fb ff ff 32 47 ff ff 8d e8 fb ff ff 88 44 3b ff 75 ae}  //weight: 1, accuracy: High
        $x_1_2 = {47 45 54 00 2f 6c 61 73 74 2e 73 6f}  //weight: 1, accuracy: High
        $x_1_3 = {5c 52 75 6e 00 00 00 47 6c 6f 62 61 6c 5c 5f 5f 64 65 63 6c 73 70 65 63}  //weight: 1, accuracy: High
        $x_1_4 = "Global\\msiff0x1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Cripack_PGCP_2147963150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cripack.PGCP!MTB"
        threat_id = "2147963150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cripack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {73 73 77 78 75 6d 73 76 6f 6c 00 00 46 79 57 6a 61 43 68 00 55 44 55 68 4a 61 66 73 43 4a 43 00 6b 6f 6f 79 44 72 56 00 55 4f 51 44 4c 6d 64 59 42 68 00 00 44 79 73 6b 48 65 45 73 45 6b 00 00 4e 61 6d 62 49 49 6f 61 74 00 00 00 67 6e 41 79 69 42 59 66 67 00 00 00 45 4a 72 45 58 69 78 42 79 00 00 00 4d 74 56 51 44 4d 50 00 55 45 67 63 58 63 56 75 43 00 00 00 4f 67 45 6d 6a 79 49 4b}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cripack_ACR_2147963442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cripack.ACR!MTB"
        threat_id = "2147963442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cripack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {88 4d b4 0f be 55 f8 0f be 45 a8 2b d0 8b 4d fc 03 ca 89 4d fc 0f be 55 bc 0f be 45 a8 2b d0 81 ea e5 03 00 00 8b 4d fc 2b ca 89 4d fc 8b 55 b0 0f be 02 0c 20 8b 4d f0 33 c8}  //weight: 2, accuracy: High
        $x_1_2 = {89 55 ec 0f be 45 b4 0f be 4d f8 03 c1 8a 55 c0 2a d0 88 55 c0 8b 45 f4 69 c0 4f ff ff ff 05 e1 01 00 00 8a 4d c0 2a c8 88 4d c0 8b 55 b0 83 c2 01 89 55 b0 8b 45 b0 0f be 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


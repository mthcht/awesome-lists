rule Trojan_Win32_Kolbot_A_2147632897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kolbot.A"
        threat_id = "2147632897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kolbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 74 72 6f 6a 5f 62 6f 74 6e 65 74 [0-2] 5c 6b 6f 6c 5c 65 72 72}  //weight: 10, accuracy: Low
        $x_1_2 = "NujZoVNMZ+2aCD" ascii //weight: 1
        $x_1_3 = "vmo7r9P+YMyF5y5MCKlgYN7Y7fVi36LX1meGkD" ascii //weight: 1
        $x_10_4 = {0f b7 fb 8b 55 00 8a 54 3a ff 0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0 43}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


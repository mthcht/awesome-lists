rule Trojan_Win32_CryptoBot_RDA_2147837230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptoBot.RDA!MTB"
        threat_id = "2147837230"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {30 01 8d 04 0f f7 75 08 0f b6 04 32 33 d2 30 41 01 8d 04 0b f7 75 08 0f b6 04 32 33 d2 30 41 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptoBot_RDB_2147837231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptoBot.RDB!MTB"
        threat_id = "2147837231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 d2 8b c6 f7 75 08 83 c6 02 8a 04 1a 33 d2 30 01 8d 04 0f f7 75 08 8d 49 02 8a 14 1a 30 51 ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptoBot_RDC_2147839821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptoBot.RDC!MTB"
        threat_id = "2147839821"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 c8 40 3d ff 00 00 00 7c f6 8b 45 08 32 ca 80 f1 0f 88 0c 06 b9 03 00 00 00 46 3b f7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


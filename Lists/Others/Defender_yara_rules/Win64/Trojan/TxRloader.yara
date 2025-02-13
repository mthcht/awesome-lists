rule Trojan_Win64_TxRloader_A_2147844259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TxRloader.A!dha"
        threat_id = "2147844259"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TxRloader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "200"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "%s\\config\\TxR\\%s.TxR.0.regtrans-ms" ascii //weight: 100
        $x_100_2 = {ff 54 24 58 44 8b 44 24 44 48 8b 4c 24 58 4c 8d 4c 24 44 ba 00 10 00 00 ff}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_TxRloader_B_2147844260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TxRloader.B!dha"
        threat_id = "2147844260"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TxRloader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {6b c0 26 2b c8 0f ?? ?? ?? ?? 41 32 48 ff f6 d1 41 88 48 ff 3b fe 72}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


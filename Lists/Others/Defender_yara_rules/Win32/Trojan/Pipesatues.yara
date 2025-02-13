rule Trojan_Win32_Pipesatues_A_2147724320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pipesatues.A!!Pipesatues.gen!A"
        threat_id = "2147724320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pipesatues"
        severity = "Critical"
        info = "Pipesatues: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {68 f0 b5 a2 56 ff d5 ff 64 24 10 e8 53 ff ff ff 5c 5c 2e 5c 70 69 70 65 5c 73 74 61 74 75 73 5f 38 30 38 30 00 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


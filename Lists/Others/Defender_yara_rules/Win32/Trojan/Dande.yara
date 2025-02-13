rule Trojan_Win32_Dande_A_2147651316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dande.A"
        threat_id = "2147651316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dande"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DANDE_INST_SCS" ascii //weight: 1
        $x_1_2 = {ff d0 8b f0 8b 56 3c 8b 44 32 78 8b 4d 0c 8b d1 03 c6 c1 ea 10 89 45 f8 85 d2 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


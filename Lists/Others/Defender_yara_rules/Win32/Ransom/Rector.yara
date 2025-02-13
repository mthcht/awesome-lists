rule Ransom_Win32_Rector_A_2147688223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Rector.A"
        threat_id = "2147688223"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Rector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {24 26 25 30 34 5c 73 76 63 68 6f 73 74 2e 65 78 65 00 00 31 00 31 00 30 00 31 00 40 24 26 25 30 34 5c [0-15] 2e 65 78 65 00 00 31 00 31 00 30 00 52 75 73 73 69 61 6e 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


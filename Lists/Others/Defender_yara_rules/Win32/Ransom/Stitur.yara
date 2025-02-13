rule Ransom_Win32_Stitur_A_2147682685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Stitur.A"
        threat_id = "2147682685"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Stitur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 05 d8 01 00 00 01 d8 83 38 00 75 05 83 c0 04 01 08 ff 30 58 61 ff 64 24 dc}  //weight: 10, accuracy: High
        $x_5_2 = {66 81 71 16 00 20 14 00 66 81 38 4d 5a 75 ?? 8b 48 3c 03 c8 81 39 50 45 00 00 75}  //weight: 5, accuracy: Low
        $x_1_3 = "svchost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Stitur_AB_2147754995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Stitur.AB"
        threat_id = "2147754995"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Stitur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {ff 10 83 c4 04 8d 05 0c 04 00 00 01 d8 ff 10 8d 05 fc 01 00 00 01 d8 50 8d 05 fc 03 00 00 01 d8 ff 10 50 8d 05 00 04 00 00}  //weight: 10, accuracy: High
        $x_10_2 = "Software\\Microsoft\\Command Processor" wide //weight: 10
        $x_10_3 = "msseces.exe" wide //weight: 10
        $x_10_4 = "c0f1decb-932f-45c1-8ac9-a39645f68e37" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


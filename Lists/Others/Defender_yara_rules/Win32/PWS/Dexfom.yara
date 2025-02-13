rule PWS_Win32_Dexfom_2147610012_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dexfom"
        threat_id = "2147610012"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexfom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 52 14 0b c0 75 5e 57 8d bd b6 fc ff ff 6a 00 6a 00 68 04 01 00 00 57 8b 55 10 52 8b 12 ff 52 0c 0b c0 75 40}  //weight: 1, accuracy: High
        $x_1_2 = {81 38 2e 7a 64 00 75 0c c7 45 ec 02 00 00 00 e9}  //weight: 1, accuracy: High
        $x_1_3 = {03 42 0c 89 47 0c c7 07 2e 7a 64 00 8b 4a 14 03 4a 10 ff 76 3c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


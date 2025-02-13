rule TrojanDropper_Win32_Pizload_B_2147610867_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Pizload.B"
        threat_id = "2147610867"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Pizload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bknxl %s %s" ascii //weight: 1
        $x_1_2 = {52 61 76 54 61 73 6b 2e 65 78 65 00 52 61 76 4d}  //weight: 1, accuracy: High
        $x_1_3 = "delself.bat" ascii //weight: 1
        $x_1_4 = {77 75 61 75 63 6c 74 2e 65 78 65 00 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


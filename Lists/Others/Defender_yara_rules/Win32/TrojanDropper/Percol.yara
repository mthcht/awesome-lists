rule TrojanDropper_Win32_Percol_B_2147650770_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Percol.B"
        threat_id = "2147650770"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Percol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 5c 41 41 56 5c 5c 43 44 72 69 76 65 72 2e 73 79 73 01}  //weight: 1, accuracy: High
        $x_1_2 = "CDriver.Inf" ascii //weight: 1
        $x_1_3 = "*CDriver" ascii //weight: 1
        $x_1_4 = {c6 85 a4 fd ff ff 50 c6 85 a5 fd ff ff 72 c6 85 a6 fd ff ff 6f c6 85 a7 fd ff ff 67 c6 85 a8 fd ff ff 72 c6 85 a9 fd ff ff 61 c6 85 aa fd ff ff 6d c6 85 ab fd ff ff 20 c6 85 ac fd ff ff 46 c6}  //weight: 1, accuracy: High
        $x_1_5 = {55 8b ec 81 ec b0 02 00 00 c7 85 b0 fd ff ff 00 00 00 00 eb 0f 8b 85 b0 fd ff ff 83 c0 01 89 85 b0 fd ff ff 83 bd b0 fd ff ff 01 7d 02 eb e6 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


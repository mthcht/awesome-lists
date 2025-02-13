rule TrojanDropper_Win32_Dinwod_B_2147711169_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dinwod.B!bit"
        threat_id = "2147711169"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dinwod"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/mcy.asp?at=upm&s13=" ascii //weight: 1
        $x_1_2 = "/moneyout.php?nickname=" ascii //weight: 1
        $x_1_3 = {8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04 a9 00 01 01 81 74 e8}  //weight: 1, accuracy: High
        $x_1_4 = "c:\\windows\\friendl.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_Win32_Dinwod_C_2147721145_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dinwod.C!bit"
        threat_id = "2147721145"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dinwod"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04 a9 00 01 01 81 74 e8}  //weight: 2, accuracy: High
        $x_3_2 = {5c 54 72 6f 6a 61 6e 5c 53 76 63 68 6f 73 74 [0-48] 5c 53 76 63 68 6f 73 74 [0-48] 2e 70 64 62}  //weight: 3, accuracy: Low
        $x_2_3 = "C:\\WINDOWS\\NetKey.dll" wide //weight: 2
        $x_2_4 = "\\NetWork\\dat.dll" ascii //weight: 2
        $x_2_5 = "\\NetWork\\svchost.exe" ascii //weight: 2
        $x_3_6 = {3a 64 65 6c 66 69 6c 65 0d 0a 65 63 68 6f 20 64 65 6c 65 74 69 6e 67 2e 2e 2e 0d 0a 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 0d 0a 64 65 6c 20 22 25 73 22 0d 0a}  //weight: 3, accuracy: High
        $x_2_7 = "Global\\_Net__thin" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}


rule TrojanDownloader_Win32_Nythug_A_2147630363_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nythug.A"
        threat_id = "2147630363"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nythug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Nullsoft Install System" ascii //weight: 10
        $x_10_2 = "\\ExecPri.dll" ascii //weight: 10
        $x_1_3 = "http://seahawk17.co.cc/" ascii //weight: 1
        $x_1_4 = "http://swiftx.co.cc/jsk5e/" ascii //weight: 1
        $x_1_5 = "http://friskylove.co.cc/" ascii //weight: 1
        $x_1_6 = "http://217.114.215.211/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Nythug_B_2147630379_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nythug.B"
        threat_id = "2147630379"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nythug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Nullsoft Install System" ascii //weight: 1
        $x_1_2 = "\\ExecPri.dll" ascii //weight: 1
        $x_1_3 = "mvNat.exe" ascii //weight: 1
        $x_1_4 = {5c 53 4d 53 63 76 68 6f 73 74 2e 65 78 65 00 68 74 74 70 3a 2f 2f 70 6c 65 78 63 6f 2e 63 6f 2e 63 63 2f 73 74 6c 63 32 2f 69 63 6d 6e 74 72 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


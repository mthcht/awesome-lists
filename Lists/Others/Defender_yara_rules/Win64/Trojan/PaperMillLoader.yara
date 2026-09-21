rule Trojan_Win64_PaperMillLoader_A_2147978543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PaperMillLoader.A!AMTB"
        threat_id = "2147978543"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PaperMillLoader"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "\\Microsoft\\Crypto\\RuntimeBroker" ascii //weight: 3
        $x_3_2 = "%s\\RuntimeBroker.exe" ascii //weight: 3
        $x_3_3 = {6c 00 69 00 62 00 63 00 75 00 72 00 6c 00 2e 00 64 00 6c 00 6c 00 5f 00 [0-5] 2e 00 64 00 6c 00 6c 00}  //weight: 3, accuracy: Low
        $x_3_4 = {6c 69 62 63 75 72 6c 2e 64 6c 6c 5f [0-5] 2e 64 6c 6c}  //weight: 3, accuracy: Low
        $x_2_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 2
        $x_2_6 = "\\libcurl.dat" ascii //weight: 2
        $x_1_7 = "%s\\libcurl.dll" ascii //weight: 1
        $x_1_8 = "@.nvdata" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}


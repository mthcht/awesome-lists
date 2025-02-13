rule Worm_Win32_Theals_2147573663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Theals.gen"
        threat_id = "2147573663"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Theals"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {e8 00 00 00 00 5a 81 ea ?? ?? 41 00 89 9a ?? 10 40 00 89 b2 ?? 10 40 00 89 ba ?? 10 40 00 89 aa ?? 10 40 00 8b da 2b c0 64 8b 38 48 8b c8 f2 af af 8b 07 66 2b c0 66 81 38 4d 5a 74 07 2d 00 00 01 00 eb f2 89 83 ?? 10 40 00}  //weight: 10, accuracy: Low
        $x_10_2 = {e8 0b 00 00 00 76 69 63 74 69 6d 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_2_3 = {e8 0d 00 00 00 61 64 76 61 70 69 33 32 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_2_4 = {e8 0b 00 00 00 75 73 65 72 33 32 2e 64 6c 6c 00}  //weight: 2, accuracy: High
        $x_1_5 = "stealth.shared.dll" ascii //weight: 1
        $x_1_6 = "c:\\stealth.worm.exe" ascii //weight: 1
        $x_1_7 = "explorer.exe c:\\stealth.worm.exe" ascii //weight: 1
        $x_1_8 = "stealth.bszip.dll" ascii //weight: 1
        $x_1_9 = "stealth.dcom.exe" ascii //weight: 1
        $x_1_10 = "stealth.ddos.exe" ascii //weight: 1
        $x_1_11 = "stealth.injector.exe" ascii //weight: 1
        $x_1_12 = "stealth.stat.exe" ascii //weight: 1
        $x_1_13 = "stealth.spam.exe" ascii //weight: 1
        $x_1_14 = "stealth.wm.exe" ascii //weight: 1
        $x_1_15 = "stealth.exe" ascii //weight: 1
        $x_1_16 = "(x) 2005 Z0MBiE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_1_*))) or
            ((1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}


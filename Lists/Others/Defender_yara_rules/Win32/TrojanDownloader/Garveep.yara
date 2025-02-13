rule TrojanDownloader_Win32_Garveep_A_2147638119_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Garveep.A"
        threat_id = "2147638119"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Garveep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c9 7e 07 80 30 ?? 40 49 75 f9}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 97 01 00 00 0f 84 ?? ?? ?? ?? 68 00 04 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Garveep_B_2147645198_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Garveep.B"
        threat_id = "2147645198"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Garveep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "error to get HDD firmware serial" ascii //weight: 3
        $x_3_2 = "-}zilla]F\\B@Hq}mbafiple[@-3)%@W\\B[@7i|d}ws@<&@G\\CI" ascii //weight: 3
        $x_2_3 = "d}w|l}aderseffi|u" ascii //weight: 2
        $x_2_4 = {3d 97 01 00 00 0f 84 ?? ?? ?? ?? 68 00 04 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Garveep_C_2147689984_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Garveep.C"
        threat_id = "2147689984"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Garveep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 0c 2e 32 d2 8d 44 24 11 bf 08 00 00 00 84 48 ff 8a 18 74 04 0a d3 eb 04 f6 d3 22 d3 83 c0 02 4f 75 eb 8b 44 24 24 88 14 2e 46 3b f0 7c d1 8b fd}  //weight: 5, accuracy: High
        $x_3_2 = {3d 97 01 00 00 0f 84 ?? ?? ?? ?? 68 00 04 00 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Garveep_D_2147690079_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Garveep.D"
        threat_id = "2147690079"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Garveep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bin/read_i.php" ascii //weight: 1
        $x_1_2 = "/bin/home/home.php" ascii //weight: 1
        $x_1_3 = "fail to get" ascii //weight: 1
        $x_1_4 = "%s?a1=%s&a2=%s&a3=%s&a4=NOTUSED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Garveep_F_2147690087_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Garveep.F"
        threat_id = "2147690087"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Garveep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 ab 66 ab [0-16] ff 15 [0-1] 20 40 00 80 3e 25 0f 85 bb 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "AntiSpyWare2Guard.exe" ascii //weight: 1
        $x_1_3 = "R03AC7F0" ascii //weight: 1
        $x_1_4 = "V3LSvc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Garveep_E_2147690090_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Garveep.E"
        threat_id = "2147690090"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Garveep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 1c 37 32 d2 8d 4d ed c7 45 08 08 00 00 00 84 59 ff 74 04 0a 11 eb 06 8a 01 f6 d0 22 d0 41 41 ff 4d 08 75 ea 88 14 37 47 3b 7d fc 7c d2}  //weight: 5, accuracy: High
        $x_3_2 = "updaairpush.ignorelist.com" ascii //weight: 3
        $x_3_3 = "c%4d%02d%02d%02d%02d%02d.jpg" ascii //weight: 3
        $x_3_4 = "-}zilla]F" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Garveep_H_2147690207_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Garveep.H"
        threat_id = "2147690207"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Garveep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {53 32 db b8 80 00 00 00 8d 78 ff 83 ff 7f 0f 87}  //weight: 5, accuracy: High
        $x_3_2 = "DEXT87" ascii //weight: 3
        $x_1_3 = "/u3/update/chkupdate.php" ascii //weight: 1
        $x_1_4 = "/u3/noupdate/update.php" ascii //weight: 1
        $x_1_5 = "/u3/update/update.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Garveep_I_2147690265_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Garveep.I"
        threat_id = "2147690265"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Garveep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {53 32 db b8 80 00 00 00 83 f8 10 7f 6a}  //weight: 5, accuracy: High
        $x_5_2 = {99 2b c2 d1 f8 85 c0 0f 8f 45 ff ff ff 88 1c 31 41 3b cf 0f 8c 32 ff ff ff}  //weight: 5, accuracy: High
        $x_2_3 = "rrecent.php" ascii //weight: 2
        $x_2_4 = "%s\\sys\\..\\%s" ascii //weight: 2
        $x_2_5 = "prtshgrd.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}


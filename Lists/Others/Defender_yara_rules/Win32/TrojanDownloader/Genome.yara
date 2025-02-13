rule TrojanDownloader_Win32_Genome_A_2147630032_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Genome.A"
        threat_id = "2147630032"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Genome"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a ff 6a 00 e8 ?? ?? ?? ?? 85 c0 74 49 e8 ?? ?? ?? ?? 3d b7 00 00 00 75 23 6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 05 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? eb 1a}  //weight: 1, accuracy: Low
        $x_1_2 = "wangyou.2288.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Genome_K_2147634173_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Genome.K"
        threat_id = "2147634173"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Genome"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 00 00 00 8b ?? 0c 8b ?? 1c 8b ?? 08 8b ?? 20 8b ?? 38 ?? 18 75 f3 80 ?? 6b 74 07 80 ?? 4b 74 02 eb e7}  //weight: 1, accuracy: Low
        $x_1_2 = {58 30 10 50}  //weight: 1, accuracy: High
        $x_1_3 = {8b 53 24 03 d0 66 8b 0c 4a 8b 53 1c 03 d0 8b 1c 8a 03 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Genome_AA_2147634353_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Genome.AA"
        threat_id = "2147634353"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Genome"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1140.co.kr" ascii //weight: 1
        $x_1_2 = "local.1140.co.kr" ascii //weight: 1
        $x_1_3 = "ingrid.exe" ascii //weight: 1
        $x_1_4 = "ingrid_update.exe" ascii //weight: 1
        $x_1_5 = "ingrid_delete.exe" ascii //weight: 1
        $x_1_6 = "axAdBarProj1.ocx" ascii //weight: 1
        $x_1_7 = "Windows 114kti" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_Genome_AB_2147634517_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Genome.AB"
        threat_id = "2147634517"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Genome"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "360rp.exe" ascii //weight: 1
        $x_1_2 = "360sd.exe" ascii //weight: 1
        $x_1_3 = "ekrn.exe" ascii //weight: 1
        $x_1_4 = "\\ssaq.exe" ascii //weight: 1
        $x_1_5 = "dnfuu.3322.org/dy/qiang.exe" ascii //weight: 1
        $x_1_6 = "C:\\windows\\asex.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Genome_AD_2147636195_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Genome.AD"
        threat_id = "2147636195"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Genome"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".officesupdate.com/update.ini" ascii //weight: 1
        $x_1_2 = ".goonmax.cn/update.ini" ascii //weight: 1
        $x_2_3 = "http://%s/%s%x&version=%d&stc=" ascii //weight: 2
        $x_2_4 = "snowhtml.txt" ascii //weight: 2
        $x_2_5 = "c:\\windows\\comlmds.log" ascii //weight: 2
        $x_2_6 = "a1.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Genome_AK_2147644495_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Genome.AK"
        threat_id = "2147644495"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Genome"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/kugou_1471.exe" ascii //weight: 1
        $x_1_2 = "/PARTNER2039.exe" ascii //weight: 1
        $x_1_3 = "ZghvfjvImvkLkggS" ascii //weight: 1
        $x_1_4 = "voyzorzeZzgzWbivfJgvmivgmR" ascii //weight: 1
        $x_1_5 = ".zguwang.com/soft/a3p/PPTV(pplive)heima_0020.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Genome_AL_2147644496_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Genome.AL"
        threat_id = "2147644496"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Genome"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kws_install.msi" ascii //weight: 1
        $x_1_2 = {2f 6b 77 73 2e 36 67 67 00 00 2e 63 6e 2f 4b 57 53 49 6e 73 74 61 6c 6c 2e 6d 73 69}  //weight: 1, accuracy: High
        $x_1_3 = {73 6f 66 74 2e 64 6f 79 6f 2e 63 6e 2f 73 6f 00 00 66 74 2f 64 6f 79 6f 5f 73 65 74 75 70 5f 31 30 30 37 5f}  //weight: 1, accuracy: High
        $x_1_4 = {2e 78 75 6e 6c 65 69 31 00 00 30 30 2e 63 6f 6d 2f 6d 73 6e 2f 73 6f 66 74 77 61 72 65 2f 70 61 72 74 6e 65 72 2f 32 6d 2f 63 70 73 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Genome_U_2147645255_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Genome.U"
        threat_id = "2147645255"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Genome"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {47 83 c0 02 0f b7 28 66 83 fd 20 77 ?? 8b c3 8b d7 e8 ?? ?? ?? ?? 8b c6 8b 33 33 c9 eb}  //weight: 2, accuracy: Low
        $x_2_2 = "cvssrv.exe -runserivce" wide //weight: 2
        $x_1_3 = "/d1.zip" wide //weight: 1
        $x_1_4 = "wdb.dll" wide //weight: 1
        $x_1_5 = "wdc.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Genome_Z_2147648169_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Genome.Z"
        threat_id = "2147648169"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Genome"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 5c 38 ff 80 e3 0f b8 ?? ?? ?? ?? 0f b6 44 30 ff 24 0f 32 d8}  //weight: 1, accuracy: Low
        $x_1_2 = "\\ntsysdll.tmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Genome_AT_2147679673_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Genome.AT"
        threat_id = "2147679673"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Genome"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 4d d4 ff 15 ?? ?? 40 00 66 c7 45 c0 94 11 ba ?? ?? 40 00 8d 4d d8 ff 15 ?? ?? 40 00 8d ?? bc}  //weight: 1, accuracy: Low
        $x_1_2 = "update.exe?mode=" ascii //weight: 1
        $x_1_3 = "dlinkddns.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


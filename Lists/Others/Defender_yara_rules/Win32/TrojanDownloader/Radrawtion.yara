rule TrojanDownloader_Win32_Radrawtion_A_2147632250_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Radrawtion.A"
        threat_id = "2147632250"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Radrawtion"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 74 0c 14 ?? 8d 44 24 14 83 c1 01 8d 70 01 8a 10 83 c0 01 84 d2 75 f7 2b c6 3b c8 72 e2}  //weight: 1, accuracy: Low
        $x_1_2 = "mqqu?**rrr+oodkcli`+fj+nw*" ascii //weight: 1
        $x_2_3 = "http://www.jjanfile.co.kr/" ascii //weight: 2
        $x_1_4 = "puadq`*rlkqwdwjda*" ascii //weight: 1
        $x_2_5 = "update/wintraroad/" ascii //weight: 2
        $x_2_6 = "CwintraroadApp" ascii //weight: 2
        $x_2_7 = {77 69 6e 74 72 61 72 6f 61 64 00}  //weight: 2, accuracy: High
        $x_1_8 = {68 cc ea 43 00 51 ff 15 18 90 43 00 68 d0 07 00 00 ff 15 bc 92 43 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


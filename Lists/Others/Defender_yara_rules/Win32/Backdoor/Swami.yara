rule Backdoor_Win32_Swami_A_2147655743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Swami.A"
        threat_id = "2147655743"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Swami"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 44 31 ff 8a 14 31 32 c2 8a d0 c0 ea ?? c0 e0 ?? 0a d0 88 14 31 49 75 ?? 8a 06 8a 4c 24 ?? 32 c1 8a c8 c0 e9 ?? c0 e0 ?? 0a c8 88 0e}  //weight: 5, accuracy: Low
        $x_1_2 = "/im/linux.php" ascii //weight: 1
        $x_1_3 = "/im/solaris.php" ascii //weight: 1
        $x_1_4 = "/im/freebsd.php" ascii //weight: 1
        $x_1_5 = "syswmi.exe" ascii //weight: 1
        $x_1_6 = "/cgi-bin/mmlogin.cgi" ascii //weight: 1
        $x_1_7 = {73 76 63 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Swami_B_2147655748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Swami.B"
        threat_id = "2147655748"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Swami"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c0 c8 03 49 88 81 ?? ?? ?? ?? 75 e8 a0 ?? ?? ?? ?? 34 35 0c 00 8a 81 ?? ?? ?? ?? 32 81}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ec 8a 06 8a c8 02 c9 02 c9 02 c9 c0 e8 05 0a c8 32 4d 08 b8 01 00 00 00 88 0e 3b f8 76 1d 8a 0c 30 8a d1 02 d2 02 d2 02 d2 c0 e9 05 0a d1 32 54 30 ff 40 88 54 30 ff}  //weight: 1, accuracy: High
        $x_1_3 = "yahoo talk update" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


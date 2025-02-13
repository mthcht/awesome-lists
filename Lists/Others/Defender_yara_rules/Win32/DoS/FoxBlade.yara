rule DoS_Win32_FoxBlade_A_2147813512_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/FoxBlade.A!dha"
        threat_id = "2147813512"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "FoxBlade"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Drivers::$INDEX_ALLOCATION" ascii //weight: 1
        $x_1_2 = "\\\\.\\EPMNTDRV\\%u" wide //weight: 1
        $x_1_3 = {53 00 65 00 c7 [0-3] 53 00 68 00 c7 [0-3] 75 00 74 00 c7 [0-3] 64 00 6f 00}  //weight: 1, accuracy: Low
        $x_1_4 = {53 5a 44 44 [0-16] 4d 5a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule DoS_Win32_FoxBlade_F_2147832778_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/FoxBlade.F!dha"
        threat_id = "2147832778"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "FoxBlade"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {8b d7 8b ce e8 ?? ?? ?? ?? 46 83 fe 64 7e ec 8b d7 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 57 68 ?? ?? ?? ?? ba ?? ?? ?? ?? c7 45 ?? 5c 00 5c 00 8d 4d c4 c7 45 ?? 3f 00 5c 00}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


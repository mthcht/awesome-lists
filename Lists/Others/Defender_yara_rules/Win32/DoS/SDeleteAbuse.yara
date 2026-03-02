rule DoS_Win32_SDeleteAbuse_CA_2147963468_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/SDeleteAbuse.CA!dha"
        threat_id = "2147963468"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "SDeleteAbuse"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 [0-32] 3a 00 [0-4] 2a 00}  //weight: 1, accuracy: Low
        $x_1_2 = "taskkill /f /im ex*" wide //weight: 1
        $x_1_3 = "shutdown -s -f -t 666" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule DoS_Win32_SDeleteAbuse_C_2147963994_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/SDeleteAbuse.C!dha"
        threat_id = "2147963994"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "SDeleteAbuse"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 64 00 65 00 6c 00 65 00 74 00 65 00 2e 00 65 00 78 00 65 00 20 00 2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 20 00 2d 00 72 00 20 00 2d 00 73 00 20 00 2d 00 71 00 20 00 ?? ?? 3a 00 [0-4] 2a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


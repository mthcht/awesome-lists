rule PWS_Win32_QQthief_L_2147711571_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQthief.L!bit"
        threat_id = "2147711571"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQthief"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 73 5c 7e 40 55 77 ?? ?? 2e 61 76 69 00 00 00 56 69 64 65 6f 4d 6f 75 73 65 50 69 63}  //weight: 2, accuracy: Low
        $x_1_2 = {25 73 2e 64 6c 6c [0-4] 55 73 65 72 33 32}  //weight: 1, accuracy: Low
        $x_1_3 = {25 73 33 32 2e 64 6c 6c [0-4] 55 73 65 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


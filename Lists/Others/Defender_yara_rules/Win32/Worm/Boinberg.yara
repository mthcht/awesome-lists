rule Worm_Win32_Boinberg_A_2147644205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Boinberg.gen!A"
        threat_id = "2147644205"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Boinberg"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {6a 56 8b 45 0c ff 90 ?? 01 00 00 50 8b 45 0c ff 90 ?? 01 00 00 6a 00 6a 03 6a 2d}  //weight: 4, accuracy: Low
        $x_4_2 = {c7 45 d0 51 ce db 25 66 c7 45 d4 8f 6c 66 c7 45 d6 72 4a}  //weight: 4, accuracy: High
        $x_1_3 = "spread.usb" ascii //weight: 1
        $x_1_4 = "update-md5" ascii //weight: 1
        $x_1_5 = "pingfreq" ascii //weight: 1
        $x_1_6 = "botkiller" ascii //weight: 1
        $x_1_7 = "spread.msn" ascii //weight: 1
        $x_1_8 = "spread.rarzip" ascii //weight: 1
        $x_1_9 = "ddos.ssyn" ascii //weight: 1
        $x_1_10 = "[STEALER]:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}


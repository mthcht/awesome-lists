rule Worm_Win32_Refroso_A_2147629584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Refroso.A"
        threat_id = "2147629584"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Refroso"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 02 33 f6 8b 54 ?? ?? 33 c0 bb ?? ?? ?? ?? 8a 04 16 33 d2 03 c5 f7 f3 33 c0 8a 04 39 2b c2 79 0f ba ff 00 00 00 2b d0 c1 ea 08 c1 e2 08 03 c2 88 04 39 8b 44 24 1c 46 41 83 c5 09 3b c8 72 bc 8b c7 5f 5d 5b 5e c3}  //weight: 1, accuracy: Low
        $x_1_2 = "/c \"for /L %%a in (1,1,30) do del \"%s\" && if exist \"%s\" ping -n 2" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


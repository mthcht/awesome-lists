rule DoS_Win32_ThornWiper_B_2147963984_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/ThornWiper.B!dha"
        threat_id = "2147963984"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "ThornWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nazareth" ascii //weight: 1
        $x_1_2 = "lnkmuiinfinf_lockicottfttcwavmidmbppffonotf" ascii //weight: 1
        $x_1_3 = "cmd.exe /e:ON /v:OFF /d /c" ascii //weight: 1
        $x_1_4 = "\\.\\NUL\\cmd.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


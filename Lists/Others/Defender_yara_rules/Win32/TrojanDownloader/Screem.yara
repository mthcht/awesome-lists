rule TrojanDownloader_Win32_Screem_AR_2147748472_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Screem.AR!MSR"
        threat_id = "2147748472"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Screem"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\INTERNAL\\REMOTE.EXE" wide //weight: 2
        $x_1_2 = "jqiuarrivikgjvdqiuf" ascii //weight: 1
        $x_1_3 = "vdpoaqrvytayoaygk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


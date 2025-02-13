rule TrojanDownloader_Win32_Filcout_A_2147686445_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Filcout.A"
        threat_id = "2147686445"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Filcout"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "updater-1341016669.us-east-1.elb.amazonaws.com" wide //weight: 5
        $x_1_2 = "softango.com/extensions/%s?source=fs" wide //weight: 1
        $x_1_3 = "Software\\FileScout" wide //weight: 1
        $x_1_4 = ".?AVdlg@filescout@@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


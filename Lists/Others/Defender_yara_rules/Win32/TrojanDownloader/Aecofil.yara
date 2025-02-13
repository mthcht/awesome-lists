rule TrojanDownloader_Win32_Aecofil_A_2147634361_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Aecofil.A"
        threat_id = "2147634361"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Aecofil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Stat.ashx?q={@ID};{@MAC};{@NET};{@CNAME};{@TIME}&Request=ExeFile" wide //weight: 1
        $x_1_2 = "000cc.com" wide //weight: 1
        $x_1_3 = "/update.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


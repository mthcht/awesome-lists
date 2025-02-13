rule TrojanDownloader_Win32_Dyfuca_AB_2147608446_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dyfuca.AB"
        threat_id = "2147608446"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyfuca"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "250"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "http://www.internet-optimizer.com/conf/xml/" ascii //weight: 100
        $x_100_2 = "http://cdn.movies-etc.com/io/legal/EULA/EULA.ctxt" ascii //weight: 100
        $x_25_3 = "C:\\Internet Optimizer" ascii //weight: 25
        $x_25_4 = "C:\\Program Files\\Internet Optimizer" ascii //weight: 25
        $x_25_5 = "C:\\Program Files\\DyFuCA" ascii //weight: 25
        $x_25_6 = "Software\\Avenue Media\\Internet Optimizer" ascii //weight: 25
        $x_25_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\AMeOpt" ascii //weight: 25
        $x_25_8 = "SOFTWARE\\Policies\\Avenue Media" ascii //weight: 25
        $x_25_9 = "ver=%s&rid=%s&cls=%s" ascii //weight: 25
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 6 of ($x_25_*))) or
            ((2 of ($x_100_*) and 2 of ($x_25_*))) or
            (all of ($x*))
        )
}


rule TrojanDownloader_Win32_Datamaikon_A_2147655020_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Datamaikon.gen!A"
        threat_id = "2147655020"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Datamaikon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "update.konamidata.com/test/" ascii //weight: 1
        $x_1_2 = "Proxy-Authorization:Basic" ascii //weight: 1
        $x_1_3 = "myAgent" ascii //weight: 1
        $x_1_4 = "Avaliable data:%u bytes" ascii //weight: 1
        $x_1_5 = {99 b9 10 27 00 00 f7 f9 8d 84 24 18 01 00 00 52 68 5c e6 41 00 8d 94 24 a0 00 00 00 52 68 50 e6 41 00 50 e8 ?? ?? 00 00 8d 8c 24 ac 03 00 00 51 8d 54 24 30 52 8d 84 24 34 01 00 00 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


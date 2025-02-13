rule TrojanDownloader_Win32_Yorcuts_A_2147725864_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Yorcuts.A"
        threat_id = "2147725864"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Yorcuts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TellmeWhyok.acl" ascii //weight: 1
        $x_1_2 = "SigVer" ascii //weight: 1
        $x_1_3 = "1200" ascii //weight: 1
        $x_1_4 = "pwefnxalks12893kanc0923jaadcaae3" ascii //weight: 1
        $x_1_5 = {8a 06 2a 01 79 02 04 5e 04 20 88 02 8a 41 01 42 41 84 c0 75 02 8b cb 8a 46 01 46 84 c0 75 e1 83 c9 ff 33 c0 f2 ae f7 d1 49 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


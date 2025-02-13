rule TrojanDownloader_Win32_Juloft_A_2147625312_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Juloft.A"
        threat_id = "2147625312"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Juloft"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.julysoft.cn/data/data.html" ascii //weight: 1
        $x_1_2 = "julysoft.exe" ascii //weight: 1
        $x_1_3 = "javascript:" ascii //weight: 1
        $x_1_4 = "about.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Juloft_A_2147625312_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Juloft.A"
        threat_id = "2147625312"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Juloft"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.julysoft.cn/data/about.html?" ascii //weight: 1
        $x_1_2 = "http://www.julysoft1.cn/data/tj/count.php?MAC=" ascii //weight: 1
        $x_1_3 = "dllcache\\cisvc.exe" ascii //weight: 1
        $x_1_4 = "sc config CiSvc start= auto" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Juloft_A_2147625312_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Juloft.A"
        threat_id = "2147625312"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Juloft"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "211"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 75 6c 79 73 6f 66 74 [0-1] 2e 63 6e 2f 64 61 74 61 2f 69 70 2e 70 68 70}  //weight: 100, accuracy: Low
        $x_100_2 = "Internet Explorer_Server" ascii //weight: 100
        $x_10_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 75 6c 79 73 6f 66 74 [0-1] 2e 63 6e 2f 64 61 74 61 2f 4c 4c 2e 74 78 74}  //weight: 10, accuracy: Low
        $x_1_4 = "LLConfig.ini" ascii //weight: 1
        $x_10_5 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 75 6c 79 73 6f 66 74 [0-1] 2e 63 6e 2f 64 61 74 61 2f 44 4a 2e 74 78 74}  //weight: 10, accuracy: Low
        $x_1_6 = "DJConfig.ini" ascii //weight: 1
        $x_100_7 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 75 6c 79 73 6f 66 74 [0-1] 2e 63 6e 2f 64 61 74 61 2f 74 6a 2f 63 6f 75 6e 74 2e 70 68 70 3f 4d 41 43 3d}  //weight: 100, accuracy: Low
        $x_100_8 = "\\Media\\Windows Navigation Start.wav" ascii //weight: 100
        $x_10_9 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 75 6c 79 73 6f 66 74 [0-1] 2e 63 6e 2f 64 61 74 61 2f 54 43 2e 74 78 74}  //weight: 10, accuracy: Low
        $x_1_10 = "TCConfig.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*) and 2 of ($x_10_*))) or
            ((3 of ($x_100_*))) or
            (all of ($x*))
        )
}


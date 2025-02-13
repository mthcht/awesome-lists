rule TrojanDownloader_Win32_Inservice_2147803776_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Inservice"
        threat_id = "2147803776"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Inservice"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dalexcars.com" ascii //weight: 1
        $x_1_2 = "GET /intercooler" ascii //weight: 1
        $x_1_3 = "Host: www." ascii //weight: 1
        $x_1_4 = "User-Agent: Mozilla/4.0 (compatible; 1-" ascii //weight: 1
        $x_1_5 = {31 39 32 2e 00}  //weight: 1, accuracy: High
        $x_1_6 = "/users/mulez/" ascii //weight: 1
        $x_1_7 = "%s\\%s%d.exe" ascii //weight: 1
        $x_1_8 = "intercooler" ascii //weight: 1
        $x_1_9 = "pony" ascii //weight: 1
        $x_1_10 = "inet_addr" ascii //weight: 1
        $x_1_11 = "socket" ascii //weight: 1
        $x_1_12 = "strtok" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}


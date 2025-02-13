rule Trojan_Win32_Spamies_A_2147685196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spamies.A"
        threat_id = "2147685196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spamies"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "/?8080" ascii //weight: 2
        $x_2_2 = "/?80&file=SenderClient.conf" ascii //weight: 2
        $x_2_3 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20100101 Firefox/21.0" ascii //weight: 2
        $x_2_4 = {74 61 62 6c 65 3d [0-16] 53 65 6e 64 47 6f 6f 67 45 6d 61 69 6c 4c 69 73 74 52 65 70 6f 72 74}  //weight: 2, accuracy: Low
        $x_2_5 = {6c 6f 63 61 6c 68 6f 73 74 [0-32] 2e 69 6e 2e 75 61}  //weight: 2, accuracy: Low
        $x_2_6 = "mail.ru" ascii //weight: 2
        $x_2_7 = "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.0)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


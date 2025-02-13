rule TrojanDownloader_Win32_Dollflort_A_2147604950_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dollflort.A"
        threat_id = "2147604950"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dollflort"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FAST-WebCrawler/3.8 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)" ascii //weight: 1
        $x_1_2 = "Accept-Encoding: deflate, gzip, x-gzip, identity, *;q=0" ascii //weight: 1
        $x_1_3 = "Googlebot/2.1 (+http://www.googlebot.com/bot.html)" ascii //weight: 1
        $x_1_4 = "TE: deflate, gzip, chunked, identity, trailers" ascii //weight: 1
        $x_1_5 = "Accept-Language: ru-RU,ru;q=0.9,en;q=0.8" ascii //weight: 1
        $x_1_6 = "Connection: Keep-Alive, TE" ascii //weight: 1
        $x_1_7 = "DOWNLOAD_AND_EXEC" ascii //weight: 1
        $x_1_8 = "SYN/ACK" ascii //weight: 1
        $x_1_9 = "POST %s HTTP/1.1" ascii //weight: 1
        $x_1_10 = "GET %s HTTP/1.1" ascii //weight: 1
        $x_1_11 = "HalfOpen Attack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


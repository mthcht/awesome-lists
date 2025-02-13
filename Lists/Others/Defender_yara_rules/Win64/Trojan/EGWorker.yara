rule Trojan_Win64_EGWorker_SA_2147849740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EGWorker.SA"
        threat_id = "2147849740"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EGWorker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36" ascii //weight: 1
        $x_1_2 = "payloop" ascii //weight: 1
        $x_1_3 = "rDOmHZs7uZiR7gPx1r6oSQuEWUlZTL23" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


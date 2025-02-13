rule TrojanDownloader_Java_Jaxmytne_A_2147711530_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Java/Jaxmytne.A"
        threat_id = "2147711530"
        type = "TrojanDownloader"
        platform = "Java: Java binaries (classes)"
        family = "Jaxmytne"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "JaXmYttnehd70TV2rac4OA==" ascii //weight: 3
        $x_1_2 = "8C1DY/kKxMkacsq1CUL/hg==" ascii //weight: 1
        $x_1_3 = "0W71/fQZ0stT4oN1oTi0LP5fOhmyO0CqYqrWgO86rBc=" ascii //weight: 1
        $x_1_4 = "42buNaKJykfTwLlWPXRdDewvp5AAgbQKzxvOaS/vVINS8WzwFLqFVQcjqXNqs93o" ascii //weight: 1
        $x_1_5 = "hp62sP0WwyUco6bq3nwBCg==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}


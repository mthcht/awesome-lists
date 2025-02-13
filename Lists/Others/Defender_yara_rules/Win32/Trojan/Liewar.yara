rule Trojan_Win32_Liewar_2147575165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Liewar"
        threat_id = "2147575165"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Liewar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Network Information" ascii //weight: 1
        $x_1_2 = "Microsoft Windows Alert" ascii //weight: 1
        $x_1_3 = "Spyware Detected on your PC." ascii //weight: 1
        $x_1_4 = "Remove it now?" ascii //weight: 1
        $x_1_5 = "gay anal sex" ascii //weight: 1
        $x_1_6 = "internet poker" ascii //weight: 1
        $x_1_7 = "online casino" ascii //weight: 1
        $x_1_8 = "hydrocodone" ascii //weight: 1
        $x_1_9 = "adipex" ascii //weight: 1
        $x_1_10 = "xanax" ascii //weight: 1
        $x_1_11 = "car insurance" ascii //weight: 1
        $x_1_12 = "valium" ascii //weight: 1
        $x_1_13 = "online pharmacy" ascii //weight: 1
        $x_1_14 = "fioricet" ascii //weight: 1
        $x_1_15 = "online gambling" ascii //weight: 1
        $x_1_16 = "cialis" ascii //weight: 1
        $x_1_17 = "auto insurance" ascii //weight: 1
        $x_1_18 = "buy phentermine" ascii //weight: 1
        $x_1_19 = "debt consolidatio" ascii //weight: 1
        $x_1_20 = "lortab" ascii //weight: 1
        $x_1_21 = "refinance" ascii //weight: 1
        $x_1_22 = "home loan" ascii //weight: 1
        $x_1_23 = "texas holdem" ascii //weight: 1
        $x_1_24 = "airline tickets" ascii //weight: 1
        $x_1_25 = "diet pills" ascii //weight: 1
        $x_1_26 = "ambien" ascii //weight: 1
        $x_1_27 = "party poker" ascii //weight: 1
        $x_1_28 = "ringtone" ascii //weight: 1
        $x_1_29 = "airlines" ascii //weight: 1
        $x_1_30 = "carisoprodol" ascii //weight: 1
        $x_1_31 = "mortgage rates" ascii //weight: 1
        $x_1_32 = "buy viagra" ascii //weight: 1
        $x_1_33 = "buy cialis" ascii //weight: 1
        $x_1_34 = "air purifiers" ascii //weight: 1
        $x_1_35 = "business" ascii //weight: 1
        $x_1_36 = "what is vicodin" ascii //weight: 1
        $x_1_37 = "online casinos" ascii //weight: 1
        $x_1_38 = "las vegas hotels" ascii //weight: 1
        $x_1_39 = "search1.php?qq=%s" ascii //weight: 1
        $x_1_40 = "http=http://127.0.0.1:8080" ascii //weight: 1
        $x_1_41 = "Internet Connection Wizard" ascii //weight: 1
        $x_1_42 = "show2.php?id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (34 of ($x*))
}


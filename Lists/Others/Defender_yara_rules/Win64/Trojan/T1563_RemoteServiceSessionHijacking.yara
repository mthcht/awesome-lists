rule Trojan_Win64_T1563_RemoteServiceSessionHijacking_A_2147846091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/T1563_RemoteServiceSessionHijacking.A"
        threat_id = "2147846091"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "T1563_RemoteServiceSessionHijacking"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ts::remote" wide //weight: 10
        $x_10_2 = "ts::sessions" wide //weight: 10
        $x_10_3 = "vault::cred" wide //weight: 10
        $x_10_4 = "vault::list" wide //weight: 10
        $x_10_5 = "sekurlsa::cloudap" wide //weight: 10
        $x_10_6 = "sekurlsa::credman" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


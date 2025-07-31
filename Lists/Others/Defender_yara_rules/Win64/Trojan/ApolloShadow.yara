rule Trojan_Win64_ApolloShadow_A_2147947962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ApolloShadow.A!dha"
        threat_id = "2147947962"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ApolloShadow"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "timestamp.digicert.com" wide //weight: 1
        $x_1_2 = "/registered" wide //weight: 1
        $x_1_3 = "certutil.exe -f -Enterprise -addstore" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


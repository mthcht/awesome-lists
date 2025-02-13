rule Trojan_MacOS_Reverseshell_A_2147914462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Reverseshell.A"
        threat_id = "2147914462"
        type = "Trojan"
        platform = "MacOS: "
        family = "Reverseshell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "socket.socket(" wide //weight: 1
        $x_1_2 = "socket.AF_INET,socket.SOCK_STREAM" wide //weight: 1
        $x_1_3 = ".connect(" wide //weight: 1
        $x_1_4 = ".spawn(//bin//bash" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


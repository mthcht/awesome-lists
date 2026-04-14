rule Trojan_Linux_SuspNodeExec_Z_2147966944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SuspNodeExec.Z!MTB"
        threat_id = "2147966944"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SuspNodeExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 00 67 00 65 00 74 00 20 00 2d 00 71 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-60] 20 00 2d 00 6f 00 20 00 2f 00 74 00 6d 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = ";chmod 777 " wide //weight: 1
        $x_1_3 = "/poop" wide //weight: 1
        $n_100_4 = "http://127.0.0.1" wide //weight: -100
        $n_100_5 = "http://10." wide //weight: -100
        $n_100_6 = "http://172." wide //weight: -100
        $n_100_7 = "http://192." wide //weight: -100
        $n_100_8 = "http://255." wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}


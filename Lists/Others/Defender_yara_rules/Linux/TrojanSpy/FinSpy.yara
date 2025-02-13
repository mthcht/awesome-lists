rule TrojanSpy_Linux_FinSpy_VB_2147809768_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Linux/FinSpy.VB!MTB"
        threat_id = "2147809768"
        type = "TrojanSpy"
        platform = "Linux: Linux platform"
        family = "FinSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2f 66 69 6e 73 70 79 [0-16] 2e 63 66 67}  //weight: 2, accuracy: Low
        $x_1_2 = "/fin_crypto.cpp" ascii //weight: 1
        $x_1_3 = "FinSpyV2" ascii //weight: 1
        $x_1_4 = "/usr/local/finfly/cfg/" ascii //weight: 1
        $x_1_5 = "FIN_TARGET" ascii //weight: 1
        $x_1_6 = ".fin_passwd" ascii //weight: 1
        $x_1_7 = "SPK.pem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}


rule Trojan_AndroidOS_Skymobi_A_2147850218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Skymobi.A"
        threat_id = "2147850218"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Skymobi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "addFileLocationInfos" ascii //weight: 1
        $x_1_2 = "WIFIorMOBILE" ascii //weight: 1
        $x_1_3 = "AppCheckretrieveXml" ascii //weight: 1
        $x_1_4 = "dangLeBackUrl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_AndroidOS_Dougalek_A_2147656071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Dougalek.A"
        threat_id = "2147656071"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Dougalek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "douga" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f 64 65 70 6f 74 2e 62 75 6c 6b 73 2e 6a 70 2f 67 65 74 ?? ?? 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_3 = "contact_id =" ascii //weight: 1
        $x_1_4 = "http_post_success" ascii //weight: 1
        $x_1_5 = "temp_text" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Dougalek_V_2147744314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Dougalek.V!MTB"
        threat_id = "2147744314"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Dougalek"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "depot.bulks.jp" ascii //weight: 1
        $x_1_2 = "Ljp/oomosirodougamatome/MainActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Dougalek_B_2147750969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Dougalek.B"
        threat_id = "2147750969"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Dougalek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "depot.bulks.jp/get" ascii //weight: 1
        $x_1_2 = "douga" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Dougalek_C_2147808359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Dougalek.C"
        threat_id = "2147808359"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Dougalek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 65 70 6f 74 2e 62 75 6c 6b 73 2e 6a 70 2f 67 65 74 ?? ?? 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_2 = "contact_id =" ascii //weight: 1
        $x_1_3 = "http_post_success" ascii //weight: 1
        $x_1_4 = "uaus_feij" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


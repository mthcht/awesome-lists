rule Ransom_AndroidOS_BLucy_A_2147754376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/BLucy.A!MTB"
        threat_id = "2147754376"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "BLucy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gapsoinasjrq9120qwpsaja0h12p14kjqeoq0r1hgf03dshnfsaphkj9579120sdjbt91599fg0bv" ascii //weight: 1
        $x_1_2 = "http/private/set_data.php" ascii //weight: 1
        $x_1_3 = "http/private/reg.php" ascii //weight: 1
        $x_1_4 = "http/private/add_log.php" ascii //weight: 1
        $x_1_5 = "keyToE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


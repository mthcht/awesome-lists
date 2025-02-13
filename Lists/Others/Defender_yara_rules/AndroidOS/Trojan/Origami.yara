rule Trojan_AndroidOS_Origami_X_2147795902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Origami.X"
        threat_id = "2147795902"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Origami"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "T3V0R29pbmcg" ascii //weight: 1
        $x_1_2 = "SW5jb21pbmcg" ascii //weight: 1
        $x_1_3 = "YOUR TEXT HERE" ascii //weight: 1
        $x_1_4 = "dnewcallingf" ascii //weight: 1
        $x_1_5 = "Removeing files" ascii //weight: 1
        $x_1_6 = "YWRkcmVzcw" ascii //weight: 1
        $x_1_7 = "Ym9keQ==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Origami_Y_2147796560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Origami.Y"
        threat_id = "2147796560"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Origami"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "testing67" ascii //weight: 1
        $x_1_2 = "Its a System Application" ascii //weight: 1
        $x_1_3 = "For fi + fi" ascii //weight: 1
        $x_1_4 = "..YOUR TEXT HERE..." ascii //weight: 1
        $x_1_5 = "in timer ++++" ascii //weight: 1
        $x_1_6 = "Lime/serviceinfo/app/qstunthong/qSensorServicehong" ascii //weight: 1
        $x_1_7 = "Can't Turn OFF Activation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


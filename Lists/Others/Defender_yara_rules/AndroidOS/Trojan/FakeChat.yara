rule Trojan_AndroidOS_FakeChat_B_2147845596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeChat.B"
        threat_id = "2147845596"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeChat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "adapurre" ascii //weight: 2
        $x_2_2 = "https://inapturst.top/" ascii //weight: 2
        $x_2_3 = "hulkrmaker" ascii //weight: 2
        $x_2_4 = "SAp22m11" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


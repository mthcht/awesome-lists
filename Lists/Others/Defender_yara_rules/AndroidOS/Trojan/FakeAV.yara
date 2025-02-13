rule Trojan_AndroidOS_FakeAV_AS_2147781832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeAV.AS!MTB"
        threat_id = "2147781832"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 72 6f 69 6a 66 [0-32] 46 61 6b 65 41 63 74 69 76 69 74 79}  //weight: 1, accuracy: Low
        $x_1_2 = "/anbuild.dex" ascii //weight: 1
        $x_1_3 = "Cleaning up:" ascii //weight: 1
        $x_1_4 = "out sms:" ascii //weight: 1
        $x_1_5 = "blockPhones" ascii //weight: 1
        $x_1_6 = "Lantivirus/pro/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeAV_A_2147783793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeAV.A!MTB"
        threat_id = "2147783793"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FakeActivity" ascii //weight: 1
        $x_1_2 = "blockPhones" ascii //weight: 1
        $x_1_3 = "NEW_OUTGOING_CALL" ascii //weight: 1
        $x_1_4 = "requestLocationUpdates" ascii //weight: 1
        $x_1_5 = "downloads/list.txt" ascii //weight: 1
        $x_1_6 = "VIRUS!!!" ascii //weight: 1
        $x_1_7 = "antivirus/pro" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


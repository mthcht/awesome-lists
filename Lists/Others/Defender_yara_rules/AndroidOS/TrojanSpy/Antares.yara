rule TrojanSpy_AndroidOS_Antares_A_2147787207_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Antares.A!MTB"
        threat_id = "2147787207"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Antares"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSG_CONTACTS_LIST_READY" ascii //weight: 1
        $x_1_2 = "getListContacts" ascii //weight: 1
        $x_1_3 = "insertAdressWithTypes" ascii //weight: 1
        $x_1_4 = "addContactFromJSON" ascii //weight: 1
        $x_1_5 = "incoming_sms_callbak" ascii //weight: 1
        $x_1_6 = "Lcom/antares/android/JSInterface/JSContacts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


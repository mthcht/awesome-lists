rule Trojan_AndroidOS_Scythe_A_2147889033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Scythe.A"
        threat_id = "2147889033"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Scythe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wrongEamil" ascii //weight: 1
        $x_1_2 = "messageFolderRetrieve" ascii //weight: 1
        $x_1_3 = "FacebookAuthenticatorService : confirmCredentials" ascii //weight: 1
        $x_1_4 = "SnsAccount DEBUG MODE ON" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


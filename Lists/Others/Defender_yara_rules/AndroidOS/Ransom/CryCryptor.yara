rule Ransom_AndroidOS_CryCryptor_A_2147758147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/CryCryptor.A!MTB"
        threat_id = "2147758147"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "CryCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.crydroid.ACTION_DECRYPTED" ascii //weight: 1
        $x_1_2 = "com.crydroid.PASSWORD" ascii //weight: 1
        $x_1_3 = "Unlocked. Personal files decrypted" ascii //weight: 1
        $x_1_4 = "PBKDF2WithHmacSHA1" ascii //weight: 1
        $x_1_5 = "/readme_now.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_AndroidOS_CryCryptor_B_2147783145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/CryCryptor.B"
        threat_id = "2147783145"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "CryCryptor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6f 6d 2e [0-32] 2e 41 43 54 49 4f 4e 5f 45 4e 43 52 59 50 54 45 44}  //weight: 1, accuracy: Low
        $x_1_2 = {63 6f 6d 2e [0-32] 2e 50 41 53 53 57 4f 52 44}  //weight: 1, accuracy: Low
        $x_1_3 = "/readme" ascii //weight: 1
        $x_1_4 = "Unlocked. Personal files decrypted" ascii //weight: 1
        $x_1_5 = ".enc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}


rule Trojan_Win64_SneakyGrunt_A_2147945430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SneakyGrunt.A!dha"
        threat_id = "2147945430"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SneakyGrunt"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "3af3begb.0ak" ascii //weight: 10
        $x_10_2 = "{\"GUID\":\"{0}\",\"Type\":{1},\"Meta\":\"{2}\",\"IV\":\"{3}\",\"EncryptedMessage\":\"{4}\",\"HMAC\":\"{5}\"}" wide //weight: 10
        $x_1_3 = "token_type" ascii //weight: 1
        $x_1_4 = "access_token" ascii //weight: 1
        $x_1_5 = "expires_in" ascii //weight: 1
        $x_1_6 = "refresh_token" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}


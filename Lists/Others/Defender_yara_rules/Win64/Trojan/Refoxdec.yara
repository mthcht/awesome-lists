rule Trojan_Win64_Refoxdec_A_2147916275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Refoxdec.A!dha"
        threat_id = "2147916275"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Refoxdec"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "getAllAuthData" ascii //weight: 4
        $x_2_2 = "SELECT encryptedUsername, encryptedPassword, hostname,httpRealm FROM moz_logins" ascii //weight: 2
        $x_1_3 = "\\signons.sqlite" ascii //weight: 1
        $x_1_4 = "\\logins.json" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win64_T1552_004_PrivateKeys_A_2147846077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/T1552_004_PrivateKeys.A"
        threat_id = "2147846077"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "T1552_004_PrivateKeys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "crypto::capi" wide //weight: 10
        $x_10_2 = "crypto::cng" wide //weight: 10
        $x_10_3 = "crypto::certificates" wide //weight: 10
        $x_10_4 = "crypto::extract" wide //weight: 10
        $x_10_5 = "crypto::keys" wide //weight: 10
        $x_10_6 = "lsadump::backupkeys" wide //weight: 10
        $x_10_7 = "sekurlsa::backupkeys" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}


rule Trojan_MacOS_SpyAgnt_K_2147840871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SpyAgnt.K!MTB"
        threat_id = "2147840871"
        type = "Trojan"
        platform = "MacOS: "
        family = "SpyAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "runtime.persistentalloc" ascii //weight: 1
        $x_1_2 = "poc/pkg/utils.Upload" ascii //weight: 1
        $x_1_3 = "crypto/cipher.NewCBCDecrypter" ascii //weight: 1
        $x_1_4 = "DialClientConnPool.GetClientConn" ascii //weight: 1
        $x_1_5 = "os.(*Process).Kill" ascii //weight: 1
        $x_1_6 = "runtime.scavengeSleep" ascii //weight: 1
        $x_1_7 = "main.exploit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}


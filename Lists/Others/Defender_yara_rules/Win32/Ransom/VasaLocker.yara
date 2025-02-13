rule Ransom_Win32_VasaLocker_MK_2147772935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/VasaLocker.MK!MTB"
        threat_id = "2147772935"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "VasaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "44"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ecdh_pub_k.bin" ascii //weight: 10
        $x_1_2 = "vasa_dbg.txt" ascii //weight: 1
        $x_1_3 = "VASA LOCKER" ascii //weight: 1
        $x_10_4 = "Your computers and servers are encrypted" ascii //weight: 10
        $x_1_5 = "@protonmail.ch" ascii //weight: 1
        $x_1_6 = "YOUR PERSONAL ID, ATTACH IT:" ascii //weight: 1
        $x_10_7 = "!!! DANGER !!!" ascii //weight: 10
        $x_10_8 = "__NIST_K571__" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


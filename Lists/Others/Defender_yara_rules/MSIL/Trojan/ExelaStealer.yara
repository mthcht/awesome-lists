rule Trojan_MSIL_ExelaStealer_CCBC_2147891294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ExelaStealer.CCBC!MTB"
        threat_id = "2147891294"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ExelaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Exela" ascii //weight: 1
        $x_1_2 = "GetWifiPasswords" ascii //weight: 1
        $x_1_3 = "GetHistory" ascii //weight: 1
        $x_1_4 = "KillProcess" ascii //weight: 1
        $x_1_5 = "GetCookies" ascii //weight: 1
        $x_1_6 = "AntiVM" ascii //weight: 1
        $x_1_7 = "wireshark" wide //weight: 1
        $x_1_8 = "regedit" wide //weight: 1
        $x_1_9 = "vboxservice" wide //weight: 1
        $x_1_10 = "processhacker" wide //weight: 1
        $x_1_11 = "ida64" wide //weight: 1
        $x_1_12 = "ollydbg" wide //weight: 1
        $x_1_13 = "sandbox" wide //weight: 1
        $x_1_14 = "cuckoo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Trojan_Win32_Tocofob_A_2147659886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tocofob.A"
        threat_id = "2147659886"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tocofob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Status: [ICMP - Already Enabled]" wide //weight: 1
        $x_1_2 = "Status: [ HTTP - Attack Enabled ]" wide //weight: 1
        $x_1_3 = "Status: [ UDP - Attack Enabled ]" wide //weight: 1
        $x_1_4 = "ICMP DDoS Status" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}


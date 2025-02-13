rule Trojan_Win32_Masson_B_2147772223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Masson.B"
        threat_id = "2147772223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Masson"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Csrss by Micosoft" ascii //weight: 1
        $x_1_2 = "Micosoft Inc" ascii //weight: 1
        $x_1_3 = "7593dbcb-ee05-44dd-a2e5-658803f5cdde" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Masson_C_2147773328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Masson.C"
        threat_id = "2147773328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Masson"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InetlMeFWSrevice" ascii //weight: 1
        $x_1_2 = "Inetl Inc." ascii //weight: 1
        $x_1_3 = "b05ac33b-3a48-489d-a29c-6dff54873b63" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


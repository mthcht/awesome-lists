rule TrojanSpy_Win32_Malatiz_A_2147711095_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Malatiz.A"
        threat_id = "2147711095"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Malatiz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SELECT username_value, password_value, signon_realm FROM logins" ascii //weight: 1
        $x_1_2 = "\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_3 = "This Computer IS not Virused" ascii //weight: 1
        $x_1_4 = "{Temp-00-aa-123-mr-bbb}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


rule Backdoor_Win32_TrickPos_A_2147730306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/TrickPos.A!MTB"
        threat_id = "2147730306"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickPos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*MICROS*" wide //weight: 1
        $x_1_2 = "STORE found: %d" wide //weight: 1
        $x_1_3 = "POS found: %d" wide //weight: 1
        $x_1_4 = "ALOHA found: %d" wide //weight: 1
        $x_1_5 = "DOMAIN GC" wide //weight: 1
        $x_1_6 = "Report successfully sent" ascii //weight: 1
        $x_1_7 = "(&(objectCategory=person)(sAMAccountName=%s))" wide //weight: 1
        $x_1_8 = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


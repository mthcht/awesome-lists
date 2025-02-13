rule Spammer_Win32_Fifesock_A_2147644065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Fifesock.A"
        threat_id = "2147644065"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Fifesock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\fb_spam\\fb_spam\\Release\\fb_spam.pdb" ascii //weight: 2
        $x_1_2 = "security_token=%s&reqId=&blogID=&hca=true&blogtitle=%s&blogspotname=%s&ok=Next" ascii //weight: 1
        $x_1_3 = "oogle.com/accounts/ServiceLogin?service=blogger&continue=https://www.blogger.com/loginz?" ascii //weight: 1
        $x_2_4 = "%s?act=fb_extended&user=%s&pass=%s&num=0&total=%s&dob=%s&status=spam" ascii //weight: 2
        $x_1_5 = "username=%s&password=%s&authenticity_token=%s" ascii //weight: 1
        $x_1_6 = "?edit=birthday" ascii //weight: 1
        $x_1_7 = "\\\\.\\pipe\\twitter" ascii //weight: 1
        $x_1_8 = "\\\\.\\pipe\\blogspot" ascii //weight: 1
        $x_1_9 = "\\\\.\\pipe\\facebook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_Fifesock_B_2147644705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Fifesock.B"
        threat_id = "2147644705"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Fifesock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 08 83 f9 7c 75 1e 8b ?? fc c6 ?? 00 8b 45 fc 83 c0 01 89 45 fc}  //weight: 2, accuracy: Low
        $x_2_2 = {ff 05 76 0c c7 05 ?? ?? ?? ?? 01 00 00 80 eb 0a c7 05 ?? ?? ?? ?? 02 00 00 80 05 00 83 bd}  //weight: 2, accuracy: Low
        $x_1_3 = "_BLOCKED_18084" ascii //weight: 1
        $x_1_4 = "%s?act=fb_get" ascii //weight: 1
        $x_1_5 = "%s?act=fb_extended" ascii //weight: 1
        $x_1_6 = "%s?act=fb_stat&num=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}


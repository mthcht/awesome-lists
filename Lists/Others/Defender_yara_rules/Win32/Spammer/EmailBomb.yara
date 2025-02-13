rule Spammer_Win32_EmailBomb_F_2147632464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/EmailBomb.F"
        threat_id = "2147632464"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "EmailBomb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "67A90AF8-5505-4cb9-AB16-73EBAF7EF784" ascii //weight: 1
        $x_1_2 = "%s?type=%s&system=%s&id=%s&n=%d&status=%s" ascii //weight: 1
        $x_1_3 = "if exist \"%s\" goto a" ascii //weight: 1
        $x_1_4 = {b9 0d 00 00 00 be ?? ?? ?? ?? 8d bc 24 ?? ?? 00 00 f3 a5 89 44 24 1c 66 a5 ff 15 ?? ?? ?? ?? 68 94 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Spammer_Win32_EmailBomb_G_2147633033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/EmailBomb.G"
        threat_id = "2147633033"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "EmailBomb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SignUp.DoPost();" ascii //weight: 1
        $x_1_2 = "/account_post.asp" ascii //weight: 1
        $x_2_3 = "%s?type=%s&system=%s&id=%s&status=%s&n=%d&extra=%s" ascii //weight: 2
        $x_2_4 = "%APPDATA%\\Microsoft\\Internet Explorer\\ccsr" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_EmailBomb_H_2147633334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/EmailBomb.H"
        threat_id = "2147633334"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "EmailBomb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 70 72 6f 74 65 63 74 79 6f 75 72 70 63 2d 31 ?? 2e 63 6f 6d 2f 69 65}  //weight: 1, accuracy: Low
        $x_1_2 = "\\LowRegistry\\DontShowMeThisDialogAgain" ascii //weight: 1
        $x_1_3 = "%s?type=%s&system=%s&id=%s&status=%s&n=%d&extra=%s" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f 70 72 6f 74 65 63 74 79 6f 75 72 70 63 2d 31 ?? 2e 63 6f 6d 2f 6f 75 74 32 2f 6d 73 6e 5f 69 6d 61 69 6c 65 72 5f 76 [0-2] 2e 74 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


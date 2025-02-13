rule Worm_Win32_Voterai_A_2147601371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Voterai.A"
        threat_id = "2147601371"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Voterai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "63"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "autorun" wide //weight: 10
        $x_10_2 = "SeShutdownPrivilege" wide //weight: 10
        $x_10_3 = "msvbvm60.dll" ascii //weight: 10
        $x_10_4 = "hh:mm:ss AMPM" wide //weight: 10
        $x_10_5 = ":10 AM" wide //weight: 10
        $x_10_6 = ":10 PM" wide //weight: 10
        $x_1_7 = "KASP" wide //weight: 1
        $x_1_8 = "NOD32" wide //weight: 1
        $x_1_9 = "NORTON" wide //weight: 1
        $x_1_10 = "MCAFEE" wide //weight: 1
        $x_1_11 = "NEME" wide //weight: 1
        $x_1_12 = "SYMAN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Voterai_D_2147624330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Voterai.D"
        threat_id = "2147624330"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Voterai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "VOTE RAILA ODINGA FOR PRESIDENT 2007" ascii //weight: 10
        $x_1_2 = "sendmail.dll" ascii //weight: 1
        $x_1_3 = "\\Software\\Microsoft\\Outlook Express\\5.0\\Mail" ascii //weight: 1
        $x_1_4 = "Bogus message code %d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Voterai_H_2147653841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Voterai.H"
        threat_id = "2147653841"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Voterai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RailaO.exe" ascii //weight: 1
        $x_1_2 = "\\Raila Odinga.exe" ascii //weight: 1
        $x_1_3 = "Raila Odinga.gif" ascii //weight: 1
        $x_1_4 = "%\\drivers\\" ascii //weight: 1
        $x_1_5 = "\\autorun.inf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}


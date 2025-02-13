rule PWS_Win32_Vidar_YA_2147731350_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Vidar.YA!MTB"
        threat_id = "2147731350"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Vidar Version:" ascii //weight: 1
        $x_1_2 = "FIREFOX PASS" ascii //weight: 1
        $x_1_3 = "\\TorBro\\Profile\\" ascii //weight: 1
        $x_1_4 = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Vidar_YB_2147733749_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Vidar.YB!MTB"
        threat_id = "2147733749"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Vidar.cpp" wide //weight: 1
        $x_1_2 = "searchString != replaceString" wide //weight: 1
        $x_1_3 = "http://ip-api.com/" ascii //weight: 1
        $x_1_4 = "*wallet*.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Vidar_YC_2147739814_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Vidar.YC!bit"
        threat_id = "2147739814"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 33 d2 8b c7 f7 f1 8b 45 ?? 8b 4d 08 8a 04 02 32 04 31 47 88 06 3b 7d 10 72 d8 0c 00 ff 75 ?? 8d 34 1f ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = ":Zone.Identifier" ascii //weight: 1
        $x_1_3 = "*wallet*.dat" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Vidar_A_2147742694_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Vidar.A"
        threat_id = "2147742694"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Vidar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "154"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "netfulfilled" ascii //weight: 1
        $x_1_2 = "mnpayments" ascii //weight: 1
        $x_1_3 = "mncache" ascii //weight: 1
        $x_1_4 = "governance" ascii //weight: 1
        $x_1_5 = "banlist" ascii //weight: 1
        $x_2_6 = "fee_estimates" ascii //weight: 2
        $x_50_7 = "walle*.dat" ascii //weight: 50
        $x_50_8 = "card_number_encrypted FROM credit_cards" ascii //weight: 50
        $x_50_9 = {43 61 72 64 3a [0-32] 4e 61 6d 65 3a [0-32] 50 61 73 73 77 6f 72 64 3a}  //weight: 50, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_50_*) and 4 of ($x_1_*))) or
            ((3 of ($x_50_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}


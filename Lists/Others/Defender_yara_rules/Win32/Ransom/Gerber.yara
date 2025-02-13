rule Ransom_Win32_Gerber_A_2147731047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gerber.A!MTB"
        threat_id = "2147731047"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gerber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your computer (or server) is blocked by Gerber 4 due a security reasons" ascii //weight: 1
        $x_1_2 = "Don't worry, if your files get a new extension" ascii //weight: 1
        $x_1_3 = "Contact to email address: memoyanov.artur79@cock.li or bestleveldaypayday@cock.li" ascii //weight: 1
        $x_1_4 = "Warning: You can't decrypt files without note: Decrypt.TXT" ascii //weight: 1
        $x_1_5 = "Contact to email address: memoyanov.artur79@bitmessage.ch or bestleveldaypayday@bitmessage.ch" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}


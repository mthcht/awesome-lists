rule Ransom_Win32_Plboy_YAA_2147924912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Plboy.YAA!MTB"
        threat_id = "2147924912"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Plboy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_2 = "Starting local drive encryption" ascii //weight: 1
        $x_1_3 = "Changing desktop wallpaper" ascii //weight: 1
        $x_1_4 = "gencrypted_message.bmp" wide //weight: 1
        $x_1_5 = "YOUR FILES ARE ENCRYPTED" wide //weight: 1
        $x_1_6 = "FOLLOW INSTRUCTIONS TO RECOVER" wide //weight: 1
        $x_1_7 = ".PLBOY" wide //weight: 1
        $x_1_8 = "Telegram.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

